/*
 * TCP Illinois congestion control.
 * Home page:
 *	http://www.ews.uiuc.edu/~shaoliu/tcpillinois/index.html
 *
 * The algorithm is described in:
 * "TCP-Illinois: A Loss and Delay-Based Congestion Control Algorithm
 *  for High-Speed Networks"
 * http://www.ifp.illinois.edu/~srikant/Papers/liubassri06perf.pdf
 *
 * Implemented from description in paper and ns-2 simulation.
 * Copyright (C) 2007 Stephen Hemminger <shemminger@linux-foundation.org>
 */

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <asm/div64.h>
#include <net/tcp.h>

#include <net/mptcp.h>//mming
#include <stdio.h>//mming

#define ALPHA_SHIFT	7
#define ALPHA_SCALE	(1u<<ALPHA_SHIFT)
#define ALPHA_MIN	((3*ALPHA_SCALE)/10)	/* ~0.3 */
#define ALPHA_MAX	(10*ALPHA_SCALE)	/* 10.0 */
#define ALPHA_BASE	ALPHA_SCALE		/* 1.0 */
#define RTT_MAX		(U32_MAX / ALPHA_MAX)	/* 3.3 secs */

#define BETA_SHIFT	6
#define BETA_SCALE	(1u<<BETA_SHIFT)
#define BETA_MIN	(BETA_SCALE/8)		/* 0.125 */
#define BETA_MAX	(BETA_SCALE/2)		/* 0.5 */
#define BETA_BASE	BETA_MAX

static int win_thresh __read_mostly = 15;
module_param(win_thresh, int, 0);
MODULE_PARM_DESC(win_thresh, "Window threshold for starting adaptive sizing");

static int theta __read_mostly = 5;
module_param(theta, int, 0);
MODULE_PARM_DESC(theta, "# of fast RTT's before full growth");

/* TCP Illinois Parameters */
struct illinois {
	u64	sum_rtt;	/* sum of rtt's measured within last rtt */
	u16	cnt_rtt;	/* # of rtts measured within last rtt */
	u32	base_rtt;	/* min of all rtt in usec */
	u32	max_rtt;	/* max of all rtt in usec */
	u32	end_seq;	/* right edge of current RTT */
	u32	alpha;		/* Additive increase */
	u32	beta;		/* Muliplicative decrease */
	u16	acked;		/* # packets acked by current ACK */
	u8	rtt_above;	/* average rtt has gone above threshold */
	u8	rtt_low;	/* # of rtts measurements below threshold */
};

/* mming*/
static int alpha_scale_den = 10;
static int alpha_scale_num = 32;
static int alpha_scale = 12;

struct mptcp_ccc {
	u64	alpha;
	bool	forced_update;
};
/* */

static void rtt_reset(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct illinois *ca = inet_csk_ca(sk);

	ca->end_seq = tp->snd_nxt;
	ca->cnt_rtt = 0;
	ca->sum_rtt = 0;

	/* TODO: age max_rtt? */
}

static void tcp_illinois_init(struct sock *sk)
{
	struct illinois *ca = inet_csk_ca(sk);

	ca->alpha = ALPHA_MAX;
	ca->beta = BETA_BASE;
	ca->base_rtt = 0x7fffffff;
	ca->max_rtt = 0;

	ca->acked = 0;
	ca->rtt_low = 0;
	ca->rtt_above = 0;

	rtt_reset(sk);
}

/* Measure RTT for each ack. */
static void tcp_illinois_acked(struct sock *sk, u32 pkts_acked, s32 rtt)
{
	struct illinois *ca = inet_csk_ca(sk);

	ca->acked = pkts_acked;

	/* dup ack, no rtt sample */
	if (rtt < 0)
		return;

	/* ignore bogus values, this prevents wraparound in alpha math */
	if (rtt > RTT_MAX)
		rtt = RTT_MAX;

	/* keep track of minimum RTT seen so far */
	if (ca->base_rtt > rtt)
		ca->base_rtt = rtt;

	/* and max */
	if (ca->max_rtt < rtt)
		ca->max_rtt = rtt;

	++ca->cnt_rtt;
	ca->sum_rtt += rtt;
}

/* Maximum queuing delay */
static inline u32 max_delay(const struct illinois *ca)
{
	return ca->max_rtt - ca->base_rtt;
}

/* Average queuing delay */
static inline u32 avg_delay(const struct illinois *ca)
{
	u64 t = ca->sum_rtt;

	do_div(t, ca->cnt_rtt);
	return t - ca->base_rtt;
}

/*
 * Compute value of alpha used for additive increase.
 * If small window then use 1.0, equivalent to Reno.
 *
 * For larger windows, adjust based on average delay.
 * A. If average delay is at minimum (we are uncongested),
 *    then use large alpha (10.0) to increase faster.
 * B. If average delay is at maximum (getting congested)
 *    then use small alpha (0.3)
 *
 * The result is a convex window growth curve.
 */
static u32 alpha(struct illinois *ca, u32 da, u32 dm)
{
	u32 d1 = dm / 100;	/* Low threshold */

	if (da <= d1) {
		/* If never got out of low delay zone, then use max */
		if (!ca->rtt_above)
			return ALPHA_MAX;

		/* Wait for 5 good RTT's before allowing alpha to go alpha max.
		 * This prevents one good RTT from causing sudden window increase.
		 */
		if (++ca->rtt_low < theta)
			return ca->alpha;

		ca->rtt_low = 0;
		ca->rtt_above = 0;
		return ALPHA_MAX;
	}

	ca->rtt_above = 1;

	/*
	 * Based on:
	 *
	 *      (dm - d1) amin amax
	 * k1 = -------------------
	 *         amax - amin
	 *
	 *       (dm - d1) amin
	 * k2 = ----------------  - d1
	 *        amax - amin
	 *
	 *             k1
	 * alpha = ----------
	 *          k2 + da
	 */

	dm -= d1;
	da -= d1;
	return (dm * ALPHA_MAX) /
		(dm + (da  * (ALPHA_MAX - ALPHA_MIN)) / ALPHA_MIN);
}

/*
 * Beta used for multiplicative decrease.
 * For small window sizes returns same value as Reno (0.5)
 *
 * If delay is small (10% of max) then beta = 1/8
 * If delay is up to 80% of max then beta = 1/2
 * In between is a linear function
 */
static u32 beta(u32 da, u32 dm)
{
	u32 d2, d3;

	d2 = dm / 10;
	if (da <= d2)
		return BETA_MIN;

	d3 = (8 * dm) / 10;
	if (da >= d3 || d3 <= d2)
		return BETA_MAX;

	/*
	 * Based on:
	 *
	 *       bmin d3 - bmax d2
	 * k3 = -------------------
	 *         d3 - d2
	 *
	 *       bmax - bmin
	 * k4 = -------------
	 *         d3 - d2
	 *
	 * b = k3 + k4 da
	 */
	return (BETA_MIN * d3 - BETA_MAX * d2 + (BETA_MAX - BETA_MIN) * da)
		/ (d3 - d2);
}

/* Update alpha and beta values once per RTT */
static void update_params(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct illinois *ca = inet_csk_ca(sk);

	if (tp->snd_cwnd < win_thresh) {
		ca->alpha = ALPHA_BASE;
		ca->beta = BETA_BASE;
	} else if (ca->cnt_rtt > 0) {
		u32 dm = max_delay(ca);
		u32 da = avg_delay(ca);

		ca->alpha = alpha(ca, da, dm);
		ca->beta = beta(da, dm);
	}

	rtt_reset(sk);
}

/*
 * In case of loss, reset to default values
 */
static void tcp_illinois_state(struct sock *sk, u8 new_state)
{
	struct illinois *ca = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		ca->alpha = ALPHA_BASE;
		ca->beta = BETA_BASE;
		ca->rtt_low = 0;
		ca->rtt_above = 0;
		rtt_reset(sk);
	}
}

/*
 * Increase window in response to successful acknowledgment.
 */
static void tcp_illinois_cong_avoid(struct sock *sk, u32 ack, u32 acked,
				    u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct illinois *ca = inet_csk_ca(sk);

	if (after(ack, ca->end_seq))
		update_params(sk);

	/* RFC2861 only increase cwnd if fully utilized */
	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	/* In slow start */
	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp, acked);

	else {
		u32 delta;

		/* snd_cwnd_cnt is # of packets since last cwnd increment */
		tp->snd_cwnd_cnt += ca->acked;
		ca->acked = 1;

		/* This is close approximation of:
		 * tp->snd_cwnd += alpha/tp->snd_cwnd
		*/
		delta = (tp->snd_cwnd_cnt * ca->alpha) >> ALPHA_SHIFT;
		if (delta >= tp->snd_cwnd) {
			tp->snd_cwnd = min(tp->snd_cwnd + delta / tp->snd_cwnd,
					   (u32) tp->snd_cwnd_clamp);
			tp->snd_cwnd_cnt = 0;
		}
	}
}

static u32 tcp_illinois_ssthresh(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct illinois *ca = inet_csk_ca(sk);

	/* Multiplicative decrease */
	return max(tp->snd_cwnd - ((tp->snd_cwnd * ca->beta) >> BETA_SHIFT), 2U);
}


/* Extract info for Tcp socket info provided via netlink. */
static void tcp_illinois_info(struct sock *sk, u32 ext,
			      struct sk_buff *skb)
{
	const struct illinois *ca = inet_csk_ca(sk);

	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcpvegas_info info = {
			.tcpv_enabled = 1,
			.tcpv_rttcnt = ca->cnt_rtt,
			.tcpv_minrtt = ca->base_rtt,
		};

		if (info.tcpv_rttcnt > 0) {
			u64 t = ca->sum_rtt;

			do_div(t, info.tcpv_rttcnt);
			info.tcpv_rtt = t;
		}
		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
	}
}

/*mming*/

static inline void mstcp_set_forced(struct sock *meta_sk, bool force)
{
	struct mptcp_ccc *mptcp_ccc = inet_csk_ca(meta_sk);
	mptcp_ccc->forced_update = force;
}

static inline bool mstcp_get_forced(struct sock *meta_sk)
{
	struct mptcp_ccc *mptcp_ccc = inet_csk_ca(meta_sk);
	return mptcp_ccc->forced_update;
}

static void mstcp_ccc_set_state(struct sock *sk, u8 ca_state)
{
	tcp_illinois_state(sk, ca_state);

	if (mptcp(tcp_sk(sk)))
	{
		mstcp_set_forced(mptcp_meta_sk(sk), 1);
	}
}

static inline u64 mstcp_ccc_scale(u32 val, int scale)
{
	return (u64) val << scale;
}

static inline void mstcp_set_alpha(struct sock *meta_sk, u64 alpha)
{
	struct mptcp_ccc *mptcp_ccc = inet_csk_ca(meta_sk);
	mptcp_ccc->alpha = alpha;
}

static inline u64 mstcp_get_alpha(struct sock *meta_sk)
{
	struct mptcp_ccc *mptcp_ccc = inet_csk_ca(meta_sk);
	return mptcp_ccc->alpha;
}

static inline int mstcp_ccc_sk_can_send(const struct sock *sk)
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt;
}

static void mstcp_ccc_recalc_alpha(struct sock *sk)
{
	struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	struct sock *sub_sk;
	int best_cwnd = 0, best_rtt = 0, can_send = 0;
	u64 max_numerator = 0, sum_denominator = 0, alpha = 1;

	if (!mpcb)
		return;

	/* Only one subflow left - fall back to normal reno-behavior
	 * 	 * (set alpha to 1)
	 * 	 	 */
	if (mpcb->cnt_established <= 1)
		goto exit;//alpha = 1

	/* Do regular alpha-calculation for multiple subflows */

	/* Find the max numerator of the alpha-calculation */
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
		u64 tmp;

		if (!mstcp_ccc_sk_can_send(sub_sk))
			continue;

		can_send++;

		/* We need to look for the path, that provides the max-value.
		 * 		 * Integer-overflow is not possible here, because
		 * 		 		 * tmp will be in u64.
		 * 		 		 		 */
		tmp = div64_u64(mstcp_ccc_scale(sub_tp->snd_cwnd, alpha_scale_num), (u64)sub_tp->srtt * sub_tp->srtt);

		if (tmp >= max_numerator) {
			max_numerator = tmp;
			best_cwnd = sub_tp->snd_cwnd;
			best_rtt = sub_tp->srtt;
		}
	}

	/* No subflow is able to send - we don't care anymore */
	if (unlikely(!can_send))
		goto exit;

	/* Calculate the denominator */
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);

		if (!mstcp_ccc_sk_can_send(sub_sk))
			continue;

		sum_denominator += div_u64(mstcp_ccc_scale(sub_tp->snd_cwnd, alpha_scale_den) * best_rtt, sub_tp->srtt);
	}

	sum_denominator *= sum_denominator;
	if (unlikely(!sum_denominator)) {
		pr_err("%s: sum_denominator == 0, cnt_established:%d\n", __func__, mpcb->cnt_established);
		mptcp_for_each_sk(mpcb, sub_sk) {
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
			pr_err("%s: pi:%d, state:%d\n, rtt:%u, cwnd: %u", __func__, sub_tp->mptcp->path_index,
					sub_sk->sk_state, sub_tp->srtt, sub_tp->snd_cwnd);
		}
	}

	alpha = div64_u64(mstcp_ccc_scale(best_cwnd, alpha_scale_num), sum_denominator);

	if (unlikely(!alpha))
		alpha = 1;

exit:
	mstcp_set_alpha(mptcp_meta_sk(sk), alpha);
}

static void mstcp_ccc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_LOSS)
		mstcp_ccc_recalc_alpha(sk);
}

static void mstcp_ccc_cong_avoid(struct sock *sk, u32 ack, u32 acked, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	int snd_cwnd;

	if (!mptcp(tp)) 
	{
		tcp_illinois_cong_avoid(sk, ack, acked, in_flight);//changed by mming
		//tcp_reno_cong_avoid(sk, ack, acked, in_flight);
		return;
	}

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		/* In "safe" area, increase. */
		tcp_slow_start(tp, acked);
		mstcp_ccc_recalc_alpha(sk);
		return;
	}

	if (mstcp_get_forced(mptcp_meta_sk(sk))) {
		mstcp_ccc_recalc_alpha(sk);
		mstcp_set_forced(mptcp_meta_sk(sk), 0);
	}

	if (mpcb->cnt_established > 1) {
		u64 alpha = mstcp_get_alpha(mptcp_meta_sk(sk));

		/* This may happen, if at the initialization, the mpcb
		 * 		 * was not yet attached to the sock, and thus
		 * 		 		 * initializing alpha failed.
		 * 		 		 		 */
		if (unlikely(!alpha))
			alpha = 1;

		snd_cwnd = (int) div_u64 ((u64) mstcp_ccc_scale(1, alpha_scale), alpha);

		/* snd_cwnd_cnt >= max (scale * tot_cwnd / alpha, cwnd)
		 * 		 * Thus, we select here the max value.
		 * 		 		 */
		if (snd_cwnd < tp->snd_cwnd)
			snd_cwnd = tp->snd_cwnd;
	} 
	else {
		snd_cwnd = tp->snd_cwnd;
	}

	if (tp->snd_cwnd_cnt >= snd_cwnd) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp) {
			tp->snd_cwnd++;
			mstcp_ccc_recalc_alpha(sk);
		}

		tp->snd_cwnd_cnt = 0;
	} 
	else 
	{
		tp->snd_cwnd_cnt++;
	}
}

static void mstcp_ccc_init(struct sock *sk)
{
	tcp_illinois_init(sk);

	if (mptcp(tcp_sk(sk))) 
	{
		mstcp_set_forced(mptcp_meta_sk(sk), 0);
		mstcp_set_alpha(mptcp_meta_sk(sk), 1);
	}
}

static struct tcp_congestion_ops tcp_illinois __read_mostly = {
	.flags		= TCP_CONG_RTT_STAMP,
	.init		= mstcp_ccc_init, //tcp_illinois_init,//changed by mming
	.cong_avoid	= mstcp_ccc_cong_avoid, //tcp_illinois_cong_avoid,//changed by mming
	.set_state	= mstcp_ccc_set_state, //tcp_illinois_state,//changed by mming
	.cwnd_event     = mstcp_ccc_cwnd_event,//added by mming
	.ssthresh	= tcp_illinois_ssthresh,
	.min_cwnd	= tcp_reno_min_cwnd,
	.get_info	= tcp_illinois_info,
	.pkts_acked	= tcp_illinois_acked,
	.owner		= THIS_MODULE,
	.name		= "illinois",
};

static int __init tcp_illinois_register(void)
{
	BUILD_BUG_ON(sizeof(struct illinois) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_illinois);
}

static void __exit tcp_illinois_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_illinois);
}

module_init(tcp_illinois_register);
module_exit(tcp_illinois_unregister);

MODULE_AUTHOR("Stephen Hemminger, Shao Liu");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Illinois");
MODULE_VERSION("1.0");

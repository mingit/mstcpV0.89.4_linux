/*
 * H-TCP congestion control. The algorithm is detailed in:
 * R.N.Shorten, D.J.Leith:
 *   "H-TCP: TCP for high-speed and long-distance networks"
 *   Proc. PFLDnet, Argonne, 2004.
 * http://www.hamilton.ie/net/htcp3.pdf
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <net/tcp.h>

#include <net/mptcp.h>//mming
#include <stdio.h>//mming

#define ALPHA_BASE	(1<<7)	/* 1.0 with shift << 7 */
#define BETA_MIN	(1<<6)	/* 0.5 with shift << 7 */
#define BETA_MAX	102	/* 0.8 with shift << 7 */

static int use_rtt_scaling __read_mostly = 1;
module_param(use_rtt_scaling, int, 0644);
MODULE_PARM_DESC(use_rtt_scaling, "turn on/off RTT scaling");

static int use_bandwidth_switch __read_mostly = 1;
module_param(use_bandwidth_switch, int, 0644);
MODULE_PARM_DESC(use_bandwidth_switch, "turn on/off bandwidth switcher");

struct htcp {
	u32	alpha;		/* Fixed point arith, << 7 */
	u8	beta;           /* Fixed point arith, << 7 */
	u8	modeswitch;	/* Delay modeswitch
				   until we had at least one congestion event */
	u16	pkts_acked;
	u32	packetcount;
	u32	minRTT;
	u32	maxRTT;
	u32	last_cong;	/* Time since last congestion event end */
	u32	undo_last_cong;

	u32	undo_maxRTT;
	u32	undo_old_maxB;

	/* Bandwidth estimation */
	u32	minB;
	u32	maxB;
	u32	old_maxB;
	u32	Bi;
	u32	lasttime;
};

/* mming for mstcp*/
static int alpha_scale_den = 10;
static int alpha_scale_num = 32;
static int alpha_scale = 12;

struct mptcp_ccc {
	u64	alpha;
	bool	forced_update;
};
/* */

static inline u32 htcp_cong_time(const struct htcp *ca)
{
	return jiffies - ca->last_cong;
}

static inline u32 htcp_ccount(const struct htcp *ca)
{
	return htcp_cong_time(ca) / ca->minRTT;
}

static inline void htcp_reset(struct htcp *ca)
{
	ca->undo_last_cong = ca->last_cong;
	ca->undo_maxRTT = ca->maxRTT;
	ca->undo_old_maxB = ca->old_maxB;

	ca->last_cong = jiffies;
}

static u32 htcp_cwnd_undo(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct htcp *ca = inet_csk_ca(sk);

	if (ca->undo_last_cong) {
		ca->last_cong = ca->undo_last_cong;
		ca->maxRTT = ca->undo_maxRTT;
		ca->old_maxB = ca->undo_old_maxB;
		ca->undo_last_cong = 0;
	}

	return max(tp->snd_cwnd, (tp->snd_ssthresh << 7) / ca->beta);
}

static inline void measure_rtt(struct sock *sk, u32 srtt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	struct htcp *ca = inet_csk_ca(sk);

	/* keep track of minimum RTT seen so far, minRTT is zero at first */
	if (ca->minRTT > srtt || !ca->minRTT)
		ca->minRTT = srtt;

	/* max RTT */
	if (icsk->icsk_ca_state == TCP_CA_Open) {
		if (ca->maxRTT < ca->minRTT)
			ca->maxRTT = ca->minRTT;
		if (ca->maxRTT < srtt &&
		    srtt <= ca->maxRTT + msecs_to_jiffies(20))
			ca->maxRTT = srtt;
	}
}

static void measure_achieved_throughput(struct sock *sk, u32 pkts_acked, s32 rtt)
{
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);
	struct htcp *ca = inet_csk_ca(sk);
	u32 now = tcp_time_stamp;

	if (icsk->icsk_ca_state == TCP_CA_Open)
		ca->pkts_acked = pkts_acked;

	if (rtt > 0)
		measure_rtt(sk, usecs_to_jiffies(rtt));

	if (!use_bandwidth_switch)
		return;

	/* achieved throughput calculations */
	if (!((1 << icsk->icsk_ca_state) & (TCPF_CA_Open | TCPF_CA_Disorder))) {
		ca->packetcount = 0;
		ca->lasttime = now;
		return;
	}

	ca->packetcount += pkts_acked;

	if (ca->packetcount >= tp->snd_cwnd - (ca->alpha >> 7 ? : 1) &&
	    now - ca->lasttime >= ca->minRTT &&
	    ca->minRTT > 0) {
		__u32 cur_Bi = ca->packetcount * HZ / (now - ca->lasttime);

		if (htcp_ccount(ca) <= 3) {
			/* just after backoff */
			ca->minB = ca->maxB = ca->Bi = cur_Bi;
		} else {
			ca->Bi = (3 * ca->Bi + cur_Bi) / 4;
			if (ca->Bi > ca->maxB)
				ca->maxB = ca->Bi;
			if (ca->minB > ca->maxB)
				ca->minB = ca->maxB;
		}
		ca->packetcount = 0;
		ca->lasttime = now;
	}
}

static inline void htcp_beta_update(struct htcp *ca, u32 minRTT, u32 maxRTT)
{
	if (use_bandwidth_switch) {
		u32 maxB = ca->maxB;
		u32 old_maxB = ca->old_maxB;
		ca->old_maxB = ca->maxB;

		if (!between(5 * maxB, 4 * old_maxB, 6 * old_maxB)) {
			ca->beta = BETA_MIN;
			ca->modeswitch = 0;
			return;
		}
	}

	if (ca->modeswitch && minRTT > msecs_to_jiffies(10) && maxRTT) {
		ca->beta = (minRTT << 7) / maxRTT;
		if (ca->beta < BETA_MIN)
			ca->beta = BETA_MIN;
		else if (ca->beta > BETA_MAX)
			ca->beta = BETA_MAX;
	} else {
		ca->beta = BETA_MIN;
		ca->modeswitch = 1;
	}
}

static inline void htcp_alpha_update(struct htcp *ca)
{
	u32 minRTT = ca->minRTT;
	u32 factor = 1;
	u32 diff = htcp_cong_time(ca);

	if (diff > HZ) {
		diff -= HZ;
		factor = 1 + (10 * diff + ((diff / 2) * (diff / 2) / HZ)) / HZ;
	}

	if (use_rtt_scaling && minRTT) {
		u32 scale = (HZ << 3) / (10 * minRTT);

		/* clamping ratio to interval [0.5,10]<<3 */
		scale = min(max(scale, 1U << 2), 10U << 3);
		factor = (factor << 3) / scale;
		if (!factor)
			factor = 1;
	}

	ca->alpha = 2 * factor * ((1 << 7) - ca->beta);
	if (!ca->alpha)
		ca->alpha = ALPHA_BASE;
}

/*
 * After we have the rtt data to calculate beta, we'd still prefer to wait one
 * rtt before we adjust our beta to ensure we are working from a consistent
 * data.
 *
 * This function should be called when we hit a congestion event since only at
 * that point do we really have a real sense of maxRTT (the queues en route
 * were getting just too full now).
 */
static void htcp_param_update(struct sock *sk)
{
	struct htcp *ca = inet_csk_ca(sk);
	u32 minRTT = ca->minRTT;
	u32 maxRTT = ca->maxRTT;

	htcp_beta_update(ca, minRTT, maxRTT);
	htcp_alpha_update(ca);

	/* add slowly fading memory for maxRTT to accommodate routing changes */
	if (minRTT > 0 && maxRTT > minRTT)
		ca->maxRTT = minRTT + ((maxRTT - minRTT) * 95) / 100;
}

static u32 htcp_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct htcp *ca = inet_csk_ca(sk);

	htcp_param_update(sk);
	return max((tp->snd_cwnd * ca->beta) >> 7, 2U);
}

static void htcp_cong_avoid(struct sock *sk, u32 ack, u32 acked, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct htcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp, acked);
	else {
		/* In dangerous area, increase slowly.
		 * In theory this is tp->snd_cwnd += alpha / tp->snd_cwnd
		 */
		if ((tp->snd_cwnd_cnt * ca->alpha)>>7 >= tp->snd_cwnd) {
			if (tp->snd_cwnd < tp->snd_cwnd_clamp)
				tp->snd_cwnd++;
			tp->snd_cwnd_cnt = 0;
			htcp_alpha_update(ca);
		} else
			tp->snd_cwnd_cnt += ca->pkts_acked;

		ca->pkts_acked = 1;
	}
}

static void htcp_init(struct sock *sk)
{
	struct htcp *ca = inet_csk_ca(sk);

	memset(ca, 0, sizeof(struct htcp));
	ca->alpha = ALPHA_BASE;
	ca->beta = BETA_MIN;
	ca->pkts_acked = 1;
	ca->last_cong = jiffies;
}

static void htcp_state(struct sock *sk, u8 new_state)
{
	switch (new_state) {
	case TCP_CA_Open:
		{
			struct htcp *ca = inet_csk_ca(sk);
			if (ca->undo_last_cong) {
				ca->last_cong = jiffies;
				ca->undo_last_cong = 0;
			}
		}
		break;
	case TCP_CA_CWR:
	case TCP_CA_Recovery:
	case TCP_CA_Loss:
		htcp_reset(inet_csk_ca(sk));
		break;
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
	htcp_state(sk, ca_state);

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
		htcp_cong_avoid(sk, ack, acked, in_flight);//changed by mming
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
	htcp_init(sk);

	if (mptcp(tcp_sk(sk))) 
	{
		mstcp_set_forced(mptcp_meta_sk(sk), 0);
		mstcp_set_alpha(mptcp_meta_sk(sk), 1);
	}
}

static struct tcp_congestion_ops htcp __read_mostly = {
	.init		= mstcp_ccc_init, //htcp_init,//changed by mming
	.cong_avoid	= mstcp_ccc_cong_avoid, //htcp_cong_avoid,//changed by mming
	.set_state	= mstcp_ccc_set_state, //htcp_state,//changed by mming
	.cwnd_event     = mstcp_ccc_cwnd_event,//added by mming
	.ssthresh	= htcp_recalc_ssthresh,
	.undo_cwnd	= htcp_cwnd_undo,
	.pkts_acked	= measure_achieved_throughput,
	.owner		= THIS_MODULE,
	.name		= "htcp",
};

static int __init htcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct htcp) > ICSK_CA_PRIV_SIZE);
	BUILD_BUG_ON(BETA_MIN >= BETA_MAX);
	return tcp_register_congestion_control(&htcp);
}

static void __exit htcp_unregister(void)
{
	tcp_unregister_congestion_control(&htcp);
}

module_init(htcp_register);
module_exit(htcp_unregister);

MODULE_AUTHOR("Baruch Even");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("H-TCP");

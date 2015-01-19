/*
 * TCP HYBLA
 *
 * TCP-HYBLA Congestion control algorithm, based on:
 *   C.Caini, R.Firrincieli, "TCP-Hybla: A TCP Enhancement
 *   for Heterogeneous Networks",
 *   International Journal on satellite Communications,
 *				       September 2004
 *    Daniele Lacamera
 *    root at danielinux.net
 */

#include <linux/module.h>
#include <net/tcp.h>
#include <net/mptcp.h>//mming
#include <stdio.h>//mming

/* Tcp Hybla structure. */
struct hybla {
	bool  hybla_en;
	u32   snd_cwnd_cents; /* Keeps increment values when it is <1, <<7 */
	u32   rho;	      /* Rho parameter, integer part  */
	u32   rho2;	      /* Rho * Rho, integer part */
	u32   rho_3ls;	      /* Rho parameter, <<3 */
	u32   rho2_7ls;	      /* Rho^2, <<7	*/
	u32   minrtt;	      /* Minimum smoothed round trip time value seen */
};

/* Hybla reference round trip time (default= 1/40 sec = 25 ms), in ms */
static int rtt0 = 25;
module_param(rtt0, int, 0644);
MODULE_PARM_DESC(rtt0, "reference rout trip time (ms)");

/* mming*/
static int alpha_scale_den = 10;
static int alpha_scale_num = 32;
static int alpha_scale = 12;

struct mptcp_ccc {
	u64	alpha;
	bool	forced_update;
};
/* */

/* This is called to refresh values for hybla parameters */
static inline void hybla_recalc_param (struct sock *sk)
{
	struct hybla *ca = inet_csk_ca(sk);

	ca->rho_3ls = max_t(u32, tcp_sk(sk)->srtt / msecs_to_jiffies(rtt0), 8);
	ca->rho = ca->rho_3ls >> 3;
	ca->rho2_7ls = (ca->rho_3ls * ca->rho_3ls) << 1;
	ca->rho2 = ca->rho2_7ls >> 7;
}

static void hybla_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct hybla *ca = inet_csk_ca(sk);

	ca->rho = 0;
	ca->rho2 = 0;
	ca->rho_3ls = 0;
	ca->rho2_7ls = 0;
	ca->snd_cwnd_cents = 0;
	ca->hybla_en = true;
	tp->snd_cwnd = 2;
	tp->snd_cwnd_clamp = 65535;

	/* 1st Rho measurement based on initial srtt */
	hybla_recalc_param(sk);

	/* set minimum rtt as this is the 1st ever seen */
	ca->minrtt = tp->srtt;
	tp->snd_cwnd = ca->rho;
}

static void hybla_state(struct sock *sk, u8 ca_state)
{
	struct hybla *ca = inet_csk_ca(sk);

	ca->hybla_en = (ca_state == TCP_CA_Open);
}

static inline u32 hybla_fraction(u32 odds)
{
	static const u32 fractions[] = {
		128, 139, 152, 165, 181, 197, 215, 234,
	};

	return (odds < ARRAY_SIZE(fractions)) ? fractions[odds] : 128;
}

/* TCP Hybla main routine.
 * This is the algorithm behavior:
 *     o Recalc Hybla parameters if min_rtt has changed
 *     o Give cwnd a new value based on the model proposed
 *     o remember increments <1
 */
static void hybla_cong_avoid(struct sock *sk, u32 ack, u32 acked,
			     u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct hybla *ca = inet_csk_ca(sk);
	u32 increment, odd, rho_fractions;
	int is_slowstart = 0;

	/*  Recalculate rho only if this srtt is the lowest */
	if (tp->srtt < ca->minrtt){
		hybla_recalc_param(sk);
		ca->minrtt = tp->srtt;
	}

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (!ca->hybla_en) {
		tcp_reno_cong_avoid(sk, ack, acked, in_flight);
		return;
	}

	if (ca->rho == 0)
		hybla_recalc_param(sk);

	rho_fractions = ca->rho_3ls - (ca->rho << 3);

	if (tp->snd_cwnd < tp->snd_ssthresh) {
		/*
		 * slow start
		 *      INC = 2^RHO - 1
		 * This is done by splitting the rho parameter
		 * into 2 parts: an integer part and a fraction part.
		 * Inrement<<7 is estimated by doing:
		 *	       [2^(int+fract)]<<7
		 * that is equal to:
		 *	       (2^int)	*  [(2^fract) <<7]
		 * 2^int is straightly computed as 1<<int,
		 * while we will use hybla_slowstart_fraction_increment() to
		 * calculate 2^fract in a <<7 value.
		 */
		is_slowstart = 1;
		increment = ((1 << min(ca->rho, 16U)) *
			hybla_fraction(rho_fractions)) - 128;
	} else {
		/*
		 * congestion avoidance
		 * INC = RHO^2 / W
		 * as long as increment is estimated as (rho<<7)/window
		 * it already is <<7 and we can easily count its fractions.
		 */
		increment = ca->rho2_7ls / tp->snd_cwnd;
		if (increment < 128)
			tp->snd_cwnd_cnt++;
	}

	odd = increment % 128;
	tp->snd_cwnd += increment >> 7;
	ca->snd_cwnd_cents += odd;

	/* check when fractions goes >=128 and increase cwnd by 1. */
	while (ca->snd_cwnd_cents >= 128) {
		tp->snd_cwnd++;
		ca->snd_cwnd_cents -= 128;
		tp->snd_cwnd_cnt = 0;
	}
	/* check when cwnd has not been incremented for a while */
	if (increment == 0 && odd == 0 && tp->snd_cwnd_cnt >= tp->snd_cwnd) {
		tp->snd_cwnd++;
		tp->snd_cwnd_cnt = 0;
	}
	/* clamp down slowstart cwnd to ssthresh value. */
	if (is_slowstart)
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_ssthresh);

	tp->snd_cwnd = min_t(u32, tp->snd_cwnd, tp->snd_cwnd_clamp);
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
	hybla_state(sk, ca_state);

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
		hybla_cong_avoid(sk, ack, acked, in_flight);//changed by mming
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
	hybla_init(sk);

	if (mptcp(tcp_sk(sk))) 
	{
		mstcp_set_forced(mptcp_meta_sk(sk), 0);
		mstcp_set_alpha(mptcp_meta_sk(sk), 1);
	}
}

static struct tcp_congestion_ops tcp_hybla __read_mostly = {
	.init		= mstcp_ccc_init, //hybla_init,//changed by mming
	.cong_avoid	= mstcp_ccc_cong_avoid, //hybla_cong_avoid,//changed by mming
	.set_state	= mstcp_ccc_set_state, //hybla_state,//changed by mming
	.cwnd_event     = mstcp_ccc_cwnd_event,//added by mming
	.ssthresh	= tcp_reno_ssthresh,
	.min_cwnd	= tcp_reno_min_cwnd,
	.owner		= THIS_MODULE,
	.name		= "hybla"
};

static int __init hybla_register(void)
{
	BUILD_BUG_ON(sizeof(struct hybla) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_hybla);
}

static void __exit hybla_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_hybla);
}

module_init(hybla_register);
module_exit(hybla_unregister);

MODULE_AUTHOR("Daniele Lacamera");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP Hybla");

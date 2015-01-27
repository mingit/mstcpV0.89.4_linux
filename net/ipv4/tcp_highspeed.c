/*
 * Sally Floyd's High Speed TCP (RFC 3649) congestion control
 *
 * See http://www.icir.org/floyd/hstcp.html
 *
 * John Heffner <jheffner@psc.edu>
 */

#include <linux/module.h>
#include <net/tcp.h>
//#include <stdio.h>//mming
#include <net/mptcp.h>//mming

/* From AIMD tables from RFC 3649 appendix B,
 * with fixed-point MD scaled <<8.
 */
static const struct hstcp_aimd_val {
	unsigned int cwnd;
	unsigned int md;
} hstcp_aimd_vals[] = {
 {     38,  128, /*  0.50 */ },
 {    118,  112, /*  0.44 */ },
 {    221,  104, /*  0.41 */ },
 {    347,   98, /*  0.38 */ },
 {    495,   93, /*  0.37 */ },
 {    663,   89, /*  0.35 */ },
 {    851,   86, /*  0.34 */ },
 {   1058,   83, /*  0.33 */ },
 {   1284,   81, /*  0.32 */ },
 {   1529,   78, /*  0.31 */ },
 {   1793,   76, /*  0.30 */ },
 {   2076,   74, /*  0.29 */ },
 {   2378,   72, /*  0.28 */ },
 {   2699,   71, /*  0.28 */ },
 {   3039,   69, /*  0.27 */ },
 {   3399,   68, /*  0.27 */ },
 {   3778,   66, /*  0.26 */ },
 {   4177,   65, /*  0.26 */ },
 {   4596,   64, /*  0.25 */ },
 {   5036,   62, /*  0.25 */ },
 {   5497,   61, /*  0.24 */ },
 {   5979,   60, /*  0.24 */ },
 {   6483,   59, /*  0.23 */ },
 {   7009,   58, /*  0.23 */ },
 {   7558,   57, /*  0.22 */ },
 {   8130,   56, /*  0.22 */ },
 {   8726,   55, /*  0.22 */ },
 {   9346,   54, /*  0.21 */ },
 {   9991,   53, /*  0.21 */ },
 {  10661,   52, /*  0.21 */ },
 {  11358,   52, /*  0.20 */ },
 {  12082,   51, /*  0.20 */ },
 {  12834,   50, /*  0.20 */ },
 {  13614,   49, /*  0.19 */ },
 {  14424,   48, /*  0.19 */ },
 {  15265,   48, /*  0.19 */ },
 {  16137,   47, /*  0.19 */ },
 {  17042,   46, /*  0.18 */ },
 {  17981,   45, /*  0.18 */ },
 {  18955,   45, /*  0.18 */ },
 {  19965,   44, /*  0.17 */ },
 {  21013,   43, /*  0.17 */ },
 {  22101,   43, /*  0.17 */ },
 {  23230,   42, /*  0.17 */ },
 {  24402,   41, /*  0.16 */ },
 {  25618,   41, /*  0.16 */ },
 {  26881,   40, /*  0.16 */ },
 {  28193,   39, /*  0.16 */ },
 {  29557,   39, /*  0.15 */ },
 {  30975,   38, /*  0.15 */ },
 {  32450,   38, /*  0.15 */ },
 {  33986,   37, /*  0.15 */ },
 {  35586,   36, /*  0.14 */ },
 {  37253,   36, /*  0.14 */ },
 {  38992,   35, /*  0.14 */ },
 {  40808,   35, /*  0.14 */ },
 {  42707,   34, /*  0.13 */ },
 {  44694,   33, /*  0.13 */ },
 {  46776,   33, /*  0.13 */ },
 {  48961,   32, /*  0.13 */ },
 {  51258,   32, /*  0.13 */ },
 {  53677,   31, /*  0.12 */ },
 {  56230,   30, /*  0.12 */ },
 {  58932,   30, /*  0.12 */ },
 {  61799,   29, /*  0.12 */ },
 {  64851,   28, /*  0.11 */ },
 {  68113,   28, /*  0.11 */ },
 {  71617,   27, /*  0.11 */ },
 {  75401,   26, /*  0.10 */ },
 {  79517,   26, /*  0.10 */ },
 {  84035,   25, /*  0.10 */ },
 {  89053,   24, /*  0.10 */ },
};

#define HSTCP_AIMD_MAX	ARRAY_SIZE(hstcp_aimd_vals)

struct hstcp {
	u32	ai;
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

static void hstcp_init(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct hstcp *ca = inet_csk_ca(sk);

	ca->ai = 0;

	/* Ensure the MD arithmetic works.  This is somewhat pedantic,
	 * since I don't think we will see a cwnd this large. :) */
	tp->snd_cwnd_clamp = min_t(u32, tp->snd_cwnd_clamp, 0xffffffff/128);
}

static void hstcp_cong_avoid(struct sock *sk, u32 ack, u32 acked, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct hstcp *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp, acked);
	else {
		/* Update AIMD parameters.
		 *
		 * We want to guarantee that:
		 *     hstcp_aimd_vals[ca->ai-1].cwnd <
		 *     snd_cwnd <=
		 *     hstcp_aimd_vals[ca->ai].cwnd
		 */
		if (tp->snd_cwnd > hstcp_aimd_vals[ca->ai].cwnd) {
			while (tp->snd_cwnd > hstcp_aimd_vals[ca->ai].cwnd &&
			       ca->ai < HSTCP_AIMD_MAX - 1)
				ca->ai++;
		} else if (ca->ai && tp->snd_cwnd <= hstcp_aimd_vals[ca->ai-1].cwnd) {
			while (ca->ai && tp->snd_cwnd <= hstcp_aimd_vals[ca->ai-1].cwnd)
				ca->ai--;
		}

		/* Do additive increase */
		if (tp->snd_cwnd < tp->snd_cwnd_clamp) {
			/* cwnd = cwnd + a(w) / cwnd */
			tp->snd_cwnd_cnt += ca->ai + 1;
			if (tp->snd_cwnd_cnt >= tp->snd_cwnd) {
				tp->snd_cwnd_cnt -= tp->snd_cwnd;
				tp->snd_cwnd++;
			}
		}
	}
}

static u32 hstcp_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct hstcp *ca = inet_csk_ca(sk);

	/* Do multiplicative decrease */
	return max(tp->snd_cwnd - ((tp->snd_cwnd * hstcp_aimd_vals[ca->ai].md) >> 8), 2U);
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
		hstcp_cong_avoid(sk, ack, acked, in_flight);//changed by mming
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
	hstcp_init(sk);

	if (mptcp(tcp_sk(sk))) 
	{
		mstcp_set_forced(mptcp_meta_sk(sk), 0);
		mstcp_set_alpha(mptcp_meta_sk(sk), 1);
	}
}

static struct tcp_congestion_ops tcp_highspeed __read_mostly = {
	.cong_avoid	= mstcp_ccc_cong_avoid,//hstcp_cong_avoid, //changed by mming
	.set_state	= mstcp_ccc_set_state, //added by mming
	.init		= mstcp_ccc_init, //hstcp_init,//chnaged by mming
	.cwnd_event     = mstcp_ccc_cwnd_event,//added by mming
	.ssthresh	= hstcp_ssthresh,
	.min_cwnd	= tcp_reno_min_cwnd,
	.owner		= THIS_MODULE,
	.name		= "highspeed"
};

static int __init hstcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct hstcp) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_highspeed);
}

static void __exit hstcp_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_highspeed);
}

module_init(hstcp_register);
module_exit(hstcp_unregister);

MODULE_AUTHOR("John Heffner");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("High Speed TCP");

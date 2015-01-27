/* Tom Kelly's Scalable TCP
 *
 * See http://www.deneholme.net/tom/scalable/
 *
 * John Heffner <jheffner@sc.edu>
 */

#include <linux/module.h>
#include <net/tcp.h>
#include <net/mptcp.h>//mming
//#include <stdio.h>//mming

/* These factors derived from the recommended values in the aer:
 * .01 and and 7/8. We use 50 instead of 100 to account for
 * delayed ack.
 */
#define TCP_SCALABLE_AI_CNT	50U
#define TCP_SCALABLE_MD_SCALE	3

/* mming*/
static int alpha_scale_den = 10;
static int alpha_scale_num = 32;
static int alpha_scale = 12;

struct mptcp_ccc {
	u64	alpha;
	bool	forced_update;
};
/* */

static void tcp_scalable_cong_avoid(struct sock *sk, u32 ack, u32 acked,
				    u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp, acked);
	else
		tcp_cong_avoid_ai(tp, min(tp->snd_cwnd, TCP_SCALABLE_AI_CNT));
}

static u32 tcp_scalable_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	return max(tp->snd_cwnd - (tp->snd_cwnd>>TCP_SCALABLE_MD_SCALE), 2U);
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
		tcp_scalable_cong_avoid(sk, ack, acked, in_flight);//changed by mming
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
	if (mptcp(tcp_sk(sk))) 
	{
		mstcp_set_forced(mptcp_meta_sk(sk), 0);
		mstcp_set_alpha(mptcp_meta_sk(sk), 1);
	}
}

static struct tcp_congestion_ops tcp_scalable __read_mostly = {
	.cong_avoid	= mstcp_ccc_cong_avoid, //tcp_scalable_cong_avoid,,//changed by mming
	.cwnd_event     = mstcp_ccc_cwnd_event,//added by mming
	.set_state	= mstcp_ccc_set_state, //added by mming
	.init		= mstcp_ccc_init, //added by mming
	.ssthresh	= tcp_scalable_ssthresh,
	.min_cwnd	= tcp_reno_min_cwnd,
	.owner		= THIS_MODULE,
	.name		= "scalable",
};

static int __init tcp_scalable_register(void)
{
	return tcp_register_congestion_control(&tcp_scalable);
}

static void __exit tcp_scalable_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_scalable);
}

module_init(tcp_scalable_register);
module_exit(tcp_scalable_unregister);

MODULE_AUTHOR("John Heffner");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Scalable TCP");

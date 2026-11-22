// SPDX-License-Identifier: GPL-2.0-only
#ifndef RTW89_PE_H
#define RTW89_PE_H

#include "core.h"

struct rtw89_pe;
struct rtw89_ampdu_params_compat;
struct ieee80211_ampdu_params;
struct ieee80211_key_conf;
struct ieee80211_sta;
struct ieee80211_vif;

#ifdef CONFIG_RTL9617C_RTW89_PE

int rtw89_pe_init(struct rtw89_dev *rtwdev);
void rtw89_pe_exit(struct rtw89_dev *rtwdev);
int rtw89_pe_attach(struct rtw89_dev *rtwdev);
void rtw89_pe_detach(struct rtw89_dev *rtwdev);
bool rtw89_pe_active(struct rtw89_dev *rtwdev);
int rtw89_pe_tx_request(struct rtw89_dev *rtwdev, struct rtw89_core_tx_request *tx_req);
int rtw89_pe_rx_poll(struct rtw89_dev *rtwdev, int budget);
void rtw89_pe_rx_intr_mask(u32 *intrs);
void rtw89_pe_rate_report(struct rtw89_dev *rtwdev, u8 macid, const struct rtw89_ra_report *report);
void rtw89_pe_ba_session(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
			 struct ieee80211_sta *sta, struct ieee80211_ampdu_params *params);
void rtw89_pe_key(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
		  struct ieee80211_sta *sta, struct ieee80211_key_conf *key, bool added);
void rtw89_pe_sta_add(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif, struct ieee80211_sta *sta);
void rtw89_pe_sta_remove(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif, struct ieee80211_sta *sta);
void rtw89_pe_sta_assoc(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
			struct ieee80211_sta *sta, bool associated);
void rtw89_pe_ap_address(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif);
int rtw89_pe_pause(struct rtw89_dev *rtwdev);
void rtw89_pe_open(struct rtw89_dev *rtwdev);
int rtw89_pe_flush_key(struct rtw89_dev *rtwdev, unsigned int index);
int rtw89_pe_wait_station(struct rtw89_dev *rtwdev, unsigned int macid, unsigned int tid);
void rtw89_pe_traffic_stop(struct rtw89_dev *rtwdev);

#else

static inline int rtw89_pe_init(struct rtw89_dev *rtwdev) { return 0; }
static inline void rtw89_pe_exit(struct rtw89_dev *rtwdev) {}
static inline int rtw89_pe_attach(struct rtw89_dev *rtwdev) { return -ENOTSUPP; }
static inline void rtw89_pe_detach(struct rtw89_dev *rtwdev) {}
static inline bool rtw89_pe_active(struct rtw89_dev *rtwdev) { return false; }
static inline int rtw89_pe_tx_request(struct rtw89_dev *rtwdev, struct rtw89_core_tx_request *tx_req)
{
	return -EOPNOTSUPP;
}
static inline int rtw89_pe_rx_poll(struct rtw89_dev *rtwdev, int budget) { return 0; }
static inline void rtw89_pe_rx_intr_mask(u32 *intrs) {}
static inline void rtw89_pe_rate_report(struct rtw89_dev *rtwdev, u8 macid,
					const struct rtw89_ra_report *report) {}
static inline void rtw89_pe_ba_session(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
				       struct ieee80211_sta *sta, struct ieee80211_ampdu_params *params) {}
static inline void rtw89_pe_key(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
				struct ieee80211_sta *sta, struct ieee80211_key_conf *key, bool added) {}
static inline void rtw89_pe_sta_add(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
				    struct ieee80211_sta *sta) {}
static inline void rtw89_pe_sta_remove(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
				       struct ieee80211_sta *sta) {}
static inline void rtw89_pe_sta_assoc(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif,
				      struct ieee80211_sta *sta, bool associated) {}
static inline void rtw89_pe_ap_address(struct rtw89_dev *rtwdev, struct ieee80211_vif *vif) {}
static inline int rtw89_pe_pause(struct rtw89_dev *rtwdev) { return 0; }
static inline void rtw89_pe_open(struct rtw89_dev *rtwdev) {}
static inline int rtw89_pe_flush_key(struct rtw89_dev *rtwdev, unsigned int index) { return 0; }
static inline int rtw89_pe_wait_station(struct rtw89_dev *rtwdev, unsigned int macid,
					unsigned int tid) { return 0; }
static inline void rtw89_pe_traffic_stop(struct rtw89_dev *rtwdev) {}

#endif

#endif

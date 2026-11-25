# SPDX-License-Identifier: GPL-2.0-only

include $(TOPDIR)/rules.mk

PKG_NAME:=rtw89-ap-firmware
PKG_RELEASE:=1

PKG_LICENSE:=Redistributable
PKG_FLAGS:=nonshared

include $(INCLUDE_DIR)/package.mk

define Package/rtw89-ap-firmware/Default
  SECTION:=firmware
  CATEGORY:=Firmware
  PKGARCH:=all
endef

define Package/rtl8852ce-ap-firmware
  $(call Package/rtw89-ap-firmware/Default)
  TITLE:=RealTek RTL8852CE access point firmware
endef

define Package/rtl8852ce-ap-firmware/description
  Access point firmware for RTL8852CE boards, selected with the
  "realtek,ap-firmware" device tree property.
endef

define Package/rtl8192xbe-ap-firmware
  $(call Package/rtw89-ap-firmware/Default)
  TITLE:=RealTek RTL8192XBE access point firmware
endef

define Build/Compile
endef

define Package/rtl8852ce-ap-firmware/install
	$(INSTALL_DIR) $(1)/lib/firmware/rtw89
	$(INSTALL_DATA) ./files/rtw8852c_ap_fw.bin $(1)/lib/firmware/rtw89/
endef

define Package/rtl8192xbe-ap-firmware/install
	$(INSTALL_DIR) $(1)/lib/firmware/rtw89
	$(INSTALL_DATA) ./files/rtw8192xb_ap_fw.bin $(1)/lib/firmware/rtw89/
endef

$(eval $(call BuildPackage,rtl8852ce-ap-firmware))
$(eval $(call BuildPackage,rtl8192xbe-ap-firmware))

#
# Copyright (C) 2017 Xue Liu <liuxuenetmail@gmail.com>
#
# This is free software, licensed under the GNU General Public License v2.

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-pkt-fwd
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-pkt-fwd
	SECTION:=lora
	CATEGORY:=lora
	SUBMENU:=LoRaWAN
	TITLE:=SX1301 Packet Forward Configuration Interface
	PKGARCH:=all
	DEPENDS:=+lora-packet-forwarder +luci-compat
endef

define Build/Compile
endef

define Package/luci-app-pkt-fwd/install
	$(INSTALL_DIR) $(1)/
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,luci-app-pkt-fwd))

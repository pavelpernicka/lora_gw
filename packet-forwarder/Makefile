include $(TOPDIR)/rules.mk

PKG_NAME:=lora-packet-forwarder
PKG_VERSION:=4.0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/lora-packet-forwarder
  SECTION:=lora
  CATEGORY:=lora
  SUBMENU:=LoRaWAN
  TITLE:=Lora Packet Forwarder
  DEPENDS:=+libloragw +libubox-lua +libuci-lua +dkjson
endef

define Package/lora-packet-forwarder/description
  Application for forwarding LoRa packets to server + offline mode
endef

define Build/Compile
    $(MAKE) CROSS_COMPILE=$(REAL_GNU_TARGET_NAME)- LGW_PATH=$(BUILD_DIR)/lora-gateway-5.0.1/libloragw -C $(PKG_BUILD_DIR)
endef

define Package/lora-packet-forwarder/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lora_pkt_fwd/lora_pkt_fwd $(1)/usr/sbin
	$(INSTALL_BIN) ./files/gen_lora_global_conf $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/lora_pkt_fwd.init $(1)/etc/init.d/lora_pkt_fwd
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DATA) ./files/lora-global.config $(1)/etc/config/lora-global
	mkdir -p $(1)/etc/lora
	mkdir -p $(1)/www
	mkdir -p $(1)/www/cgi-bin
	$(INSTALL_DATA) ./files/meteodecoder.py $(1)/etc/lora/meteodecoder.py
	$(INSTALL_DATA) ./files/meteocommon.py $(1)/etc/lora/meteocommon.py
	$(INSTALL_DATA) ./files/meteowind.py $(1)/etc/lora/meteowind.py
	$(INSTALL_DATA) ./files/template.db $(1)/etc/lora/template.db
	$(INSTALL_DATA) ./files/config.py $(1)/etc/lora/config.py
	$(INSTALL_DATA) ./files/data.html $(1)/www/data.html
	$(INSTALL_DATA) ./files/data.py $(1)/etc/lora/data.py
	$(INSTALL_DATA) ./files/data_json.py $(1)/etc/lora/data_json.py
	$(INSTALL_DATA) ./files/data_json $(1)/www/cgi-bin/data_json
	chmod +x $(1)/www/cgi-bin/data_json
	$(INSTALL_DATA) ./files/gcp.py $(1)/etc/lora/gcp.py
	$(INSTALL_DATA) ./files/chart.css $(1)/www/chart.css
	$(INSTALL_DATA) ./files/chart.js $(1)/www/chart.js
	$(INSTALL_DATA) ./files/upload_all.py $(1)/etc/lora/upload_all.py
	mkdir -p $(1)/etc/lora/certs
	#./files/certs/gen_cert.sh
	$(INSTALL_DATA) ./files/certs/rsa_private.pem $(1)/etc/lora/certs/rsa_private.pem
	$(INSTALL_DATA) ./files/certs/rsa_public.pem $(1)/etc/lora/certs/rsa_public.pem
endef

$(eval $(call BuildPackage,lora-packet-forwarder))

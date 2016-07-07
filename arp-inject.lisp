(in-package :lispcap)

(defconstant +arp-ethertype+ #X0806)
(defconstant +arp-mac-broadcast+ #XFFFFFFFFFFFF)

(defun make-arp-frame (ether-mac-dst ether-mac-src
                       arp-opcode arp-mac-src arp-ip-src arp-mac-dst arp-ip-dst)
  (make-ethernet-frame ether-mac-dst ether-mac-src +arp-ethertype+
                       (make-arp arp-opcode
                                 arp-mac-src arp-ip-src
                                 arp-mac-dst arp-ip-dst)))

(defun make-arp-unicast-query (mac-src ip-src mac-dst ip-dst)
  (make-arp-frame mac-dst mac-src +arp-oper-request+ mac-src ip-src 0 ip-dst))

(defun make-arp-broadcast-query (mac-src ip-src ip-dst)
  (make-arp-unicast-query mac-src ip-src +arp-mac-broadcast+ ip-dst))

(defun inject-arp-query (pcap-live query-func host)
  (plokami:inject pcap-live (funcall query-func host)))

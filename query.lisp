(in-package :lispcap)

;; TODO: Consider using other protocols to query host availability (e.g. MLD).
(defun prepare-unicast-query (host)
  (make-arp-unicast-query *query-src-mac*
                          *query-src-ip*
                          (host-mac host)
                          (host-ip host)))

(defun query-host (pcap-live host &optional (query-func #'prepare-host-query))
  (format t "Querying ~A...~%" (format-ip (host-ip host)))
  (plokami:inject pcap-live (funcall query-func host)))

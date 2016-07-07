(in-package :lispcap)

(defparameter *query-src-mac* #X001122334455)
(defparameter *query-src-ip* 3232235521)

(defvar *host-table* (make-hash-table))

(defun sniff (iface handler host-table timeout)
  (plokami:with-pcap-interface (pcap iface :timeout 0)
    (plokami:set-filter pcap "arp")
    (loop
       (plokami:capture pcap -1 handler)
       (query-inactive-hosts pcap host-table timeout))))

(defun parse-arp (host-table)
  (lambda (sec usec caplen len buffer)
    (with-input-from-sequence (stream buffer)
      (let* ((binary-types:*endian* :big-endian)
             (arp-datagram (parse-arp-frame sec usec caplen len buffer)))
        (with-slots (arp-header) arp-datagram
          (with-slots (mac-src ip-src) arp-header
            (update-host-activity host-table mac-src :ip ip-src)
            (print-arp arp-header)))))))

(defun query-inactive-hosts (pcap-live host-table timeout)
  (mapcar (lambda (host) (query-host pcap-live host))
          (get-inactive-hosts host-table timeout)))

(defun start (iface port timeout)
  (rest-service-start *host-table* port)
  (sniff iface (parse-arp *host-table*) *host-table* timeout))

(defun stop ()
  (rest-service-stop))

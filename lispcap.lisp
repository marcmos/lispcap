(in-package :lispcap)

(defvar binary-types:*endian* :big-endian)

(defclass host ()
  ((mac :accessor host-mac
        :initarg :mac)
   (ip :accessor host-ip
       :initarg :ip)
   (last-activity :accessor host-last-activity
                  :initarg :last-activity)))

(defun sniff (iface handler)
  (plokami:with-pcap-interface (pcap iface :timeout 0)
    (plokami:set-filter pcap "arp")
    (loop (plokami:capture pcap -1 handler))))

(defun parse-arp (host-table)
  (lambda (sec usec caplen len buffer)
    (with-input-from-sequence (stream buffer)
      (let* ((binary-types:*endian* :big-endian)
             (arp-datagram (parse-arp-frame sec usec caplen len buffer)))
        (with-slots (arp-header) arp-datagram
          (with-slots (mac-src ip-src) arp-header
            (update-host-activity host-table mac-src :ip ip-src)
            (print-arp arp-header)))))))

(defun start (iface port)
  (let ((host-table (make-hash-table)))
    (rest-service-start host-table port)
    (sniff iface (parse-arp host-table))))

(defun stop ()
   (rest-service-stop))

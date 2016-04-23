(in-package :lispcap)

(defclass host ()
  ((mac :accessor host-mac
        :initarg :mac)
   (ip :accessor host-ip
       :initarg :ip)
   (last-activity :accessor host-last-activity
                  :initarg :last-activity)))

(defun update-host-table (table mac &key (ip nil))
  (setf (gethash mac table)
        (make-instance 'host
                       :mac mac
                       :ip ip
                       :last-activity (get-universal-time))))
                       
(defun sniff (iface handler)
  (plokami:with-pcap-interface (pcap iface :timeout 0)
    (plokami:set-filter pcap "arp")
    (loop (plokami:capture pcap -1 handler))))

(defun parse-arp (host-table)
  (lambda (sec usec caplen len buffer)
    (with-input-from-sequence (stream buffer)
      (let* ((binary-types:*endian* :big-endian)
             (arp-datagram (parse-frame sec usec caplen len buffer)))
        (with-slots (arp-header) arp-datagram
          (with-slots (mac-src ip-src) arp-header
            (update-host-table host-table mac-src :ip ip-src)
            (print-arp arp-header)))))))

(defun dump-table (table)
  (apply #'concatenate 'string (loop
                                  for host being the hash-value of table
                                  collect (format nil "~A ~A ~A~%"
                                                  (format-mac (host-mac host))
                                                  (format-ip (host-ip host))
                                                  (- (get-universal-time) (host-last-activity host))))))

(defun start (iface port)
  (let ((host-table (make-hash-table)))
    (rest-service-start host-table port)
    (sniff iface (parse-arp host-table))))

(defun stop ()
  (rest-service-stop))

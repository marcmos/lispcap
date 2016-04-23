(defpackage :lispcap
  (:use :common-lisp
        :binary-types
        :flexi-streams
        :plokami))

(in-package :lispcap)

(define-unsigned maclen 6)

(define-binary-class ethernet-header ()
  ((mac-dst :binary-type maclen)
   (mac-src :binary-type maclen)
   (type :binary-type u16)))

(define-binary-class arp-header ()
   ((htype :binary-type u16)
    (ptype :binary-type u16)
    (hlen :binary-type u8)
    (plen :binary-type u8)
    (opcode :binary-type u16)
    (mac-src :binary-type maclen)
    (ip-src :binary-type u32)
    (mac-dst :binary-type maclen)
    (ip-dst :binary-type u32)))

(defclass capture-metadata ()
  ((sec :initarg :sec)
   (usec :initarg :usec)
   (caplen :initarg :caplen)
   (len :initarg :len)))

(defclass arp-capture ()
  ((ethernet-header :initarg :ethernet-header)
   (arp-header :initarg :arp-header)
   (capture-metadata :initarg :capture-metadata)))

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
                       
(defun format-mac (mac)
  (apply #'format nil "~2,'0X:~2,'0X:~2,'0X:~2,'0X:~2,'0X:~2,'0X"
	 (nreverse (loop repeat 6
                      for x = mac then (truncate x 256)
                      collect (nth-value 1 (truncate x 256))))))

(defun format-ip (ip)
  (apply #'format nil "~D.~D.~D.~D"
	 (nreverse (loop repeat 4
                      for x = ip then (truncate x 256)
                      collect (nth-value 1 (truncate x 256))))))

(defparameter *host-table* (make-hash-table))

(defun print-arp (datagram)
  (with-slots (mac-src mac-dst opcode ip-src ip-dst) datagram
    (format t
            "~A (~A) → ~A (~A) (~[?~;request~;response~])~%"
            (format-mac mac-src)
            (format-ip ip-src)
            (format-mac mac-dst)
            (format-ip ip-dst)
            opcode)))

(defun sniff (iface handler)
  (with-pcap-interface (pcap iface :timeout 0)
    (set-filter pcap "arp")
    (loop (capture pcap -1 handler))))

(defun parse-frame (sec usec caplen len buffer)
  (with-input-from-sequence (buffer-stream buffer)
    (let ((binary-types:*endian* :big-endian))
      (make-instance 'arp-capture
                     :ethernet-header (read-binary 'ethernet-header buffer-stream)
                     :arp-header (read-binary 'arp-header buffer-stream)
                     :capture-metadata (make-instance 'capture-metadata
                                                      :sec sec
                                                      :usec usec
                                                      :caplen caplen
                                                      :len len)))))

(defun parse-arp (sec usec caplen len buffer)
  (with-input-from-sequence (stream buffer)
    (let* ((binary-types:*endian* :big-endian)
           (arp-datagram (parse-frame sec usec caplen len buffer)))
      (with-slots (arp-header) arp-datagram
        (with-slots (mac-src ip-src) arp-header
          (update-host-table *host-table* mac-src :ip ip-src)
          (print-arp arp-header))))))

(defun dump-table (table)
  (apply #'concatenate 'string (loop
                                  for host being the hash-value of table
                                  collect (format nil "~A ~A ~A~%"
                                                  (format-mac (host-mac host))
                                                  (format-ip (host-ip host))
                                                  (- (get-universal-time) (host-last-activity host))))))

(hunchentoot:define-easy-handler (hosts-handler :uri "/hosts") ()
  (setf (hunchentoot:content-type*) "text/plain")
  (dump-table *host-table*))

(defvar *hunchentoot-acceptor* (make-instance 'hunchentoot:easy-acceptor :port 8080))
(hunchentoot:start *hunchentoot-acceptor*)

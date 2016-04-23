(defpackage :lispcap
  (:use :common-lisp
        :binary-types
        :flexi-streams
        :plokami))

(in-package :lispcap)

(define-unsigned maclen 6)

(define-binary-class arp-packet ()
  ((mac-dst :binary-type maclen)
   (mac-src :binary-type maclen)
   (type :binary-type u16)
   (htype :binary-type u16)
   (ptype :binary-type u16)
   (hlen :binary-type u8)
   (plen :binary-type u8)
   (opcode :binary-type u16)
   (arp-sender-mac :binary-type maclen)
   (sender-ip :binary-type u32)
   (arp-target-mac :binary-type maclen)
   (target-ip :binary-type u32)))

(defclass host ()
  ((mac :accessor host-mac
        :initarg :mac)
   (ip :accessor host-ip
       :initarg :ip)
   (last-activity :accessor host-last-activity
                  :initarg :last-activity)))

(defparameter *host-table* (make-hash-table))
(defun update-entry-table (table mac &key (ip nil))
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

(defun print-arp (datagram)
  (with-slots (mac-src mac-dst opcode sender-ip target-ip) datagram
    (format t
            "~A (~A) → ~A (~A) (~[?~;request~;response~])~%"
            (format-mac mac-src)
            (format-ip sender-ip)
            (format-mac mac-dst)
            (format-ip target-ip)
            opcode)))

(defun sniff (iface handler)
  (with-pcap-interface (pcap iface :timeout 0)
    (set-filter pcap "arp")
    (loop (capture pcap -1 handler))))

(defun parse-arp (sec usec caplen len buffer)
  (declare (ignore sec)
           (ignore usec)
           (ignore caplen)
           (ignore len))
  (with-input-from-sequence (stream buffer)
    (let* ((binary-types:*endian* :big-endian)
           (arp-datagram (read-binary 'arp-packet stream)))
      (print-arp arp-datagram)
      (update-entry-table *host-table*
                          (slot-value arp-datagram 'mac-src)
                          :ip (slot-value arp-datagram 'sender-ip))
      (dump-table *host-table* nil))))

(defun dump-table (table filename)
  (loop
     for host being the hash-value of table
     do (format t "~A ~A~%"
                (format-mac (slot-value host 'mac))
                (format-ip (slot-value host 'ip)))))

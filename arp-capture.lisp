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

(defun print-arp (datagram)
  (with-slots (mac-src mac-dst opcode ip-src ip-dst) datagram
    (format t
            "~A (~A) → ~A (~A) (~[?~;request~;response~])~%"
            (format-mac mac-src)
            (format-ip ip-src)
            (format-mac mac-dst)
            (format-ip ip-dst)
            opcode)))

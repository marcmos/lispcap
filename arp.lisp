(in-package :lispcap)

(defconstant +arp-htype-ethernet+ 1)
(defconstant +arp-ptype-ip+ #X800)
(defconstant +arp-plen-ip+ 4)
(defconstant +arp-oper-request+ 1)
(defconstant +arp-oper-response+ 2)

(define-binary-class arp ()
  ((htype :binary-type u16 :initarg :htype)
   (ptype :binary-type u16 :initarg :ptype)
   (hlen :binary-type u8 :initarg :hlen)
   (plen :binary-type u8 :initarg :plen)
   (opcode :binary-type u16 :initarg :opcode)
   (mac-src :binary-type maclen :initarg :mac-src)
   (ip-src :binary-type u32 :initarg :ip-src)
   (mac-dst :binary-type maclen :initarg :mac-dst)
   (ip-dst :binary-type u32 :initarg :ip-dst)))

(defun make-arp (opcode mac-src ip-src mac-dst ip-dst)
  (with-binary-output-to-vector
      (buffer-vector (make-array (list (sizeof 'arp))
                                 :element-type '(unsigned-byte 8)
                                 :fill-pointer 0))
    (let ((binary-types:*endian* :big-endian))
      (write-binary 'arp buffer-vector
                    (make-instance 'arp
                                   :htype +arp-htype-ethernet+
                                   :ptype +arp-ptype-ip+
                                   :hlen (sizeof 'maclen)
                                   :plen +arp-plen-ip+
                                   :opcode opcode
                                   :mac-src mac-src
                                   :ip-src ip-src
                                   :mac-dst mac-dst
                                   :ip-dst ip-dst)))
    buffer-vector))

(defun print-arp (datagram)
  (with-slots (mac-src mac-dst opcode ip-src ip-dst) datagram
    (format t
            "~A (~A) → ~A (~A) (~[?~;request~;response~])~%"
            (format-mac mac-src)
            (format-ip ip-src)
            (format-mac mac-dst)
            (format-ip ip-dst)
            opcode)))

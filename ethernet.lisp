(in-package :lispcap)

(define-unsigned maclen 6)
(defconstant +ethernet-payload-min-length+ 46)

(define-binary-class ethernet-header ()
  ((mac-dst :binary-type maclen :initarg :mac-dst)
   (mac-src :binary-type maclen :initarg :mac-src)
   (type :binary-type u16 :initarg :type)))

(defun make-ethernet-header (mac-dst mac-src type)
  (with-binary-output-to-vector
      (buffer-vector (make-array (list (sizeof 'ethernet-header))
                          :element-type '(unsigned-byte 8)
                          :fill-pointer 0))
    (let ((binary-types:*endian* :big-endian))
      (write-binary 'ethernet-header buffer-vector
                    (make-instance 'ethernet-header
                                   :mac-dst mac-dst
                                   :mac-src mac-src
                                   :type type))
      buffer-vector)))

(defun pad-ethernet-payload (payload)
  (if (< (length payload) +ethernet-payload-min-length+)
      (adjust-array payload
                    (list +ethernet-payload-min-length+)
                    :fill-pointer t)
      payload))

(defun make-ethernet-frame (mac-dst mac-src type payload)
  (concatenate '(vector (unsigned-byte 8))
               (make-ethernet-header mac-dst mac-src type)
               (pad-ethernet-payload payload)))

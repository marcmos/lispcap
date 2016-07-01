(in-package :lispcap)

(defclass capture-metadata ()
  ((sec :initarg :sec)
   (usec :initarg :usec)
   (caplen :initarg :caplen)
   (len :initarg :len)))

(defclass arp-capture ()
  ((ethernet-header :initarg :ethernet-header)
   (arp-header :initarg :arp-header)
   (capture-metadata :initarg :capture-metadata)))

(defun parse-arp-frame (sec usec caplen len buffer)
   (with-input-from-sequence (buffer-stream buffer)
    (let ((binary-types:*endian* :big-endian))
      (make-instance 'arp-capture
                     :ethernet-header (read-binary 'ethernet-header
                                                   buffer-stream)
                     :arp-header (read-binary 'arp buffer-stream)
                     :capture-metadata (make-instance 'capture-metadata
                                                      :sec sec
                                                      :usec usec
                                                      :caplen caplen
                                                      :len len)))))

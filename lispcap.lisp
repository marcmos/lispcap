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
   (opcode :binary-type u16)))

(defun parse-mac (number)
  (apply #'format nil "~2,'0X:~2,'0X:~2,'0X:~2,'0X:~2,'0X:~2,'0X"
	 (nreverse (loop repeat 6
                      for x = number then (truncate x 256)
                      collect (nth-value 1 (truncate x 256))))))

(defun parse-arp (sec usec caplen len buffer)
  (declare (ignore sec)
           (ignore usec)
           (ignore caplen)
           (ignore len))
  (with-input-from-sequence (stream buffer)
    (let* ((binary-types:*endian* :big-endian)
           (arp-datagram (read-binary 'arp-packet stream)))
      (with-slots (mac-src mac-dst opcode) arp-datagram
        (format t "~%")
        (format t "Source MAC: ~A~%" (parse-mac mac-src))
        (format t "Destination MAC: ~A~%" (parse-mac mac-dst))
        (format t "Opcode: ~[?~;request~;response~]~%" opcode)))))

(defun sniff (iface handler)
  (with-pcap-interface (pcap iface :timeout 0)
    (set-filter pcap "arp")
    (loop (capture pcap -1 handler))))
ls

(in-package :lispcap)

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

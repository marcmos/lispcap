(in-package :lispcap)

(defun update-host-activity (table mac &key (ip nil))
  (setf (gethash mac table)
        (make-instance 'host
                       :mac mac
                       :ip ip
                       :last-activity (get-universal-time))))

(defun print-host-table (table)
  (apply #'concatenate
         'string
         (loop
            for host being the hash-value of table
            collect (format nil "~A ~A ~A~%"
                            (format-mac (host-mac host))
                            (format-ip (host-ip host))
                            (- (get-universal-time)
                               (host-last-activity host))))))

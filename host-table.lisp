(in-package :lispcap)

(defclass host ()
  ((mac :accessor host-mac
        :initarg :mac)
   (ip :accessor host-ip
       :initarg :ip)
   (last-activity :accessor host-last-activity
                  :initarg :last-activity)))

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

(defun get-inactive-hosts (table timeout)
  (let ((inactive-hosts '())
        (current-time (get-universal-time)))
    (maphash (lambda (mac host)
               (declare (ignore mac))
               (if (>= (- current-time (host-last-activity host)) timeout)
                   (push host inactive-hosts)))
             table)
    inactive-hosts))

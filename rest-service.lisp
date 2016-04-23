(in-package :lispcap)

;; TODO: move into the separate module
(defun rest-service-start (table port)
  (hunchentoot:define-easy-handler (hosts-handler :uri "/hosts") ()
    (setf (hunchentoot:content-type*) "text/plain")
    (dump-table table))
  (defvar *hunchentoot-acceptor* (make-instance 'hunchentoot:easy-acceptor :port port))
  (hunchentoot:start *hunchentoot-acceptor*))

(defun rest-service-stop ()
  (hunchentoot:stop *hunchentoot-acceptor*))

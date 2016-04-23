(asdf:defsystem #:lispcap
  :depends-on (#:binary-types
               #:flexi-streams
               #:plokami
               #:hunchentoot)
  :components ((:file "package")
               (:file "format-address")
               (:file "arp-capture")
               (:file "rest-service")
               (:file "lispcap")))

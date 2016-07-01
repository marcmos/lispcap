(asdf:defsystem #:lispcap
  :depends-on (#:binary-types
               #:flexi-streams
               #:plokami
               #:hunchentoot)
  :components ((:file "package")
               (:file "format-address")
               (:file "ethernet")
               (:file "arp")
               (:file "arp-capture")
               (:file "arp-inject")
               (:file "host-table")
               (:file "rest-service")
               (:file "lispcap")))

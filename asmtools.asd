(ql:quickload :elf)
(ql:quickload :cffi)
(defpackage #:asmtools-pkg
  (:use :cl :asdf :cffi ))

(in-package :asmtools-pkg)

(asdf:defsystem :asmtools
;;  (:pretty-name "Assembly Tools")
  :serial t
  :components ((:file "asmtools")))
	


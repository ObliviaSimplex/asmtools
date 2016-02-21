(defpackage :asmtools
  (:use :common-lisp))

(in-package :asmtools)

(sb-ext:unlock-package :sb-vm)

(import '(sb-assem:inst sb-vm::make-ea)) 

;; "A macro for defining delimiter read-macros"
;; from Paul Graham's On Lisp, Ch. 17, fig. 17.4
(defmacro defdelim (left right parms &body body)
  `(ddfn ,left ,right #'(lambda ,parms ,@body)))

(let ((rpar (get-macro-character #\) )))
  (defun ddfn (left right fn)
    (set-macro-character right rpar)
    (set-dispatch-macro-character #\# left
                                  #'(lambda (stream char1 char2)
                                      (declare (ignorable char1 char2))
                                      (apply fn
                                             (read-delimited-list
                                              right stream t))))))

(defun sapify (seq)
  (sb-sys:vector-sap
   (make-array (length seq)
               :element-type '(unsigned-byte 8)
               :initial-contents (coerce seq 'list))))

;; this might or might not come in handy...
;; #[a b c d] will be read as a system-area-pointer to bytes a b c d...
(defdelim #\[ #\] (&rest bytes)
  (sapify bytes))

(defun objdump (seq &optional len)
  "Reads a sequence of bytes, interprets them as machine-code
instructions, and returns their disassembly as a string. Sort of like
an in-house objdump."
  (with-output-to-string (*standard-output*)
    (let ((sap (sapify seq)))
      (sb-sys:with-pinned-objects (sap)
        (sb-disassem:disassemble-memory sap (or len (length seq)))))))


(defun characters (seq)
  "Prints every human-readable character in the order in which it appears.
Prints . for unreadable characters."
  (coerce
   (loop for byte in seq collect
        (if (and (>= byte #x20) (< byte #x7F)) (code-char byte) #\.)) 'string))


(defun strings (seq &optional (minlen 3))
  "Essentially the same as the Unix utility."
  (let ((strs)
        (tmp))
    (loop for byte in seq do
         (cond ((and (>= byte #x20) (< byte #x7F))
                (push (code-char byte) tmp))
               ((>= (length tmp) minlen)
                (push (coerce (reverse tmp) 'string) strs)
                (setf tmp nil))
               (:default (setf tmp nil))))
    (reverse strs)))


(defun load-bin (path)
  ;; This can't possibly be the best way to read in a binary file, but it works.
  (with-open-file (stream path :direction :input :element-type '(unsigned-byte 8))
    (let ((bytes nil))
      (loop while (car (push (read-byte stream nil nil) bytes)))
      (reverse (cdr bytes)))))


(defun subupto (seq upto)
  (subseq seq 0 (min upto (length seq))))


;; note that gadgets% has almost exactly the same structure as strings
;; is there some common idiom here that we could abstract into a macro?
;; or would that just make it more complicated?
(defparameter *ret* '(#xC3))

(defun retp (byte)
  (member byte *ret*))

(defparameter *avoid-insts*
  '(#x5D ;; POP RBP
    ))

(defun gadgets% (bytes &optional (maximum-gadget-length))
  (let ((gadgets)
        (maxlen (or maximum-gadget-length (length bytes)))
        (tmp))
    (loop for byte in bytes do
         (push byte tmp)
         (when (retp byte)
           (push (reverse (subupto tmp maxlen)) gadgets)
           (setf tmp nil)))
    (reverse gadgets)))

(defun gadgets-from-file (path &optional (maximum-gadget-length 32))
   (loop for gadget in (gadgets%  (load-bin path) maximum-gadget-length) do
        (format t "~%; ****************************************************
~A~%" (objdump gadget))))

(defun hexify ()
  (setq *print-base* (if (= #x10 *print-base*) #xA #x10))
  (setq *read-base* (if (= #x10 *read-base*) #xA #x10))
  (format t "Setting *print-base* and *read-base* to #x~X, #x~X...~%"
          *print-base* *read-base*))
        
;; finding gadgets:
;;
;; gadgets to avoid:
;; * gadgets ending with leave, followed by ret. leave performs a pop ebp.
;; * pop ebp.
;; -- we don't want to mess up our stack frame (probably)

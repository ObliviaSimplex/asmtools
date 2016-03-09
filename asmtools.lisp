
(defpackage :asmtools
  (:use :common-lisp
        :cffi))

(in-package :asmtools)

#+sbcl
(sb-ext:unlock-package :sb-vm)

#+sbcl
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

#+sbcl
(export 'sapify)
#+sbcl
(defun sapify (seq)
  (sb-sys:vector-sap
   (make-array (length seq)
               :element-type '(unsigned-byte 8)
               :initial-contents (coerce seq 'list))))

;; this might or might not come in handy...
;; #[a b c d] will be read as a system-area-pointer to bytes a b c d...
(defdelim #\[ #\] (&rest bytes)
  (sapify bytes))

#+sbcl
(export 'objdump)
#+sbcl
(defun objdump (seq &optional len)
  "Reads a sequence of bytes, interprets them as machine-code
instructions, and returns their disassembly as a string. Sort of like
an in-house objdump."
  (with-output-to-string (*standard-output*)
    (let ((sap (sapify seq)))
      (sb-sys:with-pinned-objects (sap)
        (sb-disassem:disassemble-memory sap (or len (length seq)))))))

(export 'characters)
(defun characters (seq)
  "Prints every human-readable character in the order in which it appears.
Prints . for unreadable characters."
  (coerce
   (loop for byte in seq collect
        (if (and (>= byte #x20) (< byte #x7F)) (code-char byte) #\.)) 'string))

(export 'strings)
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

(export 'load-bin)
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
(defparameter *x86-ret* '(#xC3))

(export 'retp)
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


#+sbcl
(defun gadgets-from-file (path &optional (maximum-gadget-length 32))
   (loop for gadget in (gadgets%  (load-bin path) maximum-gadget-length) do
        (format t "~%; ****************************************************
~A~%" (objdump gadget))))

(export 'hexify)
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

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; mucking around at the object level means we need to handle signals
;; when something breaks
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

;; this bit here is from Rosetta Code

(defvar *SIGINT*   2)
(defvar *SIGSEGV* 11)

(defmacro set-signal-handler (signo &body body)
  (let ((handler (gensym "HANDLER")))
    `(progn
      (cffi:defcallback ,handler :void ((signo :int))
        (declare (ignore signo))
        ,@body)
      (cffi:foreign-funcall "signal" :int ,signo :pointer
                            (cffi:callback ,handler)))))

;; ----------------------------------------------------------------------



;; (defvar *initial* (get-internal-real-time))

;; (set-signal-handler *SIGINT*
;;   (format t "Ran for ~a seconds~&" (/ (- (get-internal-real-time) *initial*)
;;                                       internal-time-units-per-second)))
  ;;  (quit))

;; (let ((i 0))
;;   (loop do
;;        (format t "~a~&" (incf i))
;;        (sleep 0.5)))






;;; --- now some more portable functions: will definitely work
;;; --- on CCL, at the very least.

;; these are going to be architecture dependent. 

(defparameter *x86_64-machine-code-prefix*
  '(#x53 #x51 #x52 #x56 #x57 #x41 #x50 #x41 #x51 #x41 #x52 #x41
    #x53 #x41 #x54 #x41 #x55 #x41 #x56 #x41 #x57 #x55 #x48 #x89 #xe5))
;; which disassembles to
;;
;; 00:       53               PUSH RBX
;; 01:       51               PUSH RCX
;; 02:       52               PUSH RDX
;; 03:       56               PUSH RSI
;; 04:       57               PUSH RDI
;; 05:       4150             PUSH R8
;; 07:       4151             PUSH R9
;; 09:       4152             PUSH R10
;; 0B:       4153             PUSH R11
;; 0D:       4154             PUSH R12
;; 0F:       4155             PUSH R13
;; 11:       4156             PUSH R14
;; 13:       4157             PUSH R15
;; 15:       55               PUSH RBP
;; 16:       4889E5           MOV RBP, RSP


(defparameter machine-code-suffix
  '(#x48 #x89 #xec #x41 #x5f #x41 #x5e #x41 #x5d #x41 #x5c #x41
    #x5b #x41 #x5a #x41 #x59 #x41 #x58 #x5f #x5e #x5a #x59 #x5b #xc3))
;; which disassembles to
;;
;; 70:       4889EC           MOV RSP, RBP
;; 73:       415F             POP R15
;; 75:       415E             POP R14
;; 77:       415D             POP R13
;; 79:       415C             POP R12
;; 7B:       415B             POP R11
;; 7D:       415A             POP R10
;; 7F:       4159             POP R9
;; 81:       4158             POP R8
;; 83:       5F               POP RDI
;; 84:       5E               POP RSI
;; 85:       5A               POP RDX
;; 86:       59               POP RCX
;; 87:       5B               POP RBX
;; 88:       C3               RET


;; we still need to filter the code for a few forbidden instructions
;; "DON'T TOUCH RSP, RSI, OR RBP" should suffice...

(defmacro call-code (code types-and-args)
  "Pokes machine code into memory and calls it as a function. 
Types-and-args should be an unquoted list of the form
 :cffi-type-keyword argument :cffi-type-keyword argument [etc]
 :cffi-type-keyword
where the final type keyword specifies the return type."
  `(let ((ptr (cffi:foreign-alloc :unsigned-char
                                  :initial-contents ,code)))
    (unwind-protect 
          (cffi:foreign-funcall-pointer ptr () ,@types-and-args)
       (cffi:foreign-free ptr))))


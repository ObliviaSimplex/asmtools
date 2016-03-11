
(defpackage :asmtools
  (:use :common-lisp
        :cffi))

(in-package :asmtools)
(cffi:load-foreign-library
 #P"~/quicklisp/local-projects/asmtools/c/libhatchery.so")
;; may need to change this, depending on where things are.

#+SBCL
(SB-EXT:UNLOCK-PACKAGE :SB-VM)

;;#+SBCL
;;(IMPORT '(SB-ASSEM:INST SB-VM::MAKE-EA)) 



;; "A MACRO FOR DEFINING DELIMITER READ-MACROS"
;; FROM PAUL GRAHAM'S ON LISP, CH. 17, FIG. 17.4
(DEFMACRO DEFDELIM (LEFT RIGHT PARMS &BODY BODY)
  `(DDFN ,LEFT ,RIGHT #'(LAMBDA ,PARMS ,@BODY)))

(LET ((RPAR (GET-MACRO-CHARACTER #\) )))
  (DEFUN DDFN (LEFT RIGHT FN)
    (SET-MACRO-CHARACTER RIGHT RPAR)
    (SET-DISPATCH-MACRO-CHARACTER #\# LEFT
                                  #'(LAMBDA (STREAM CHAR1 CHAR2)
                                      (DECLARE (IGNORABLE CHAR1 CHAR2))
                                      (APPLY FN
                                             (READ-DELIMITED-LIST
                                              RIGHT STREAM T))))))

#+SBCL
(EXPORT 'SAPIFY)
#+SBCL
(DEFUN SAPIFY (SEQ)
  (SB-SYS:VECTOR-SAP
   (MAKE-ARRAY (LENGTH SEQ)
               :ELEMENT-TYPE '(UNSIGNED-BYTE 8)
               :INITIAL-CONTENTS (COERCE SEQ 'LIST))))

;; THIS MIGHT OR MIGHT NOT COME IN HANDY...
;; #[A B C D] WILL BE READ AS A SYSTEM-AREA-POINTER TO BYTES A B C D...
(DEFDELIM #\[ #\] (&REST BYTES)
  (SAPIFY BYTES))


(EXPORT 'OBJDUMP)
#+SBCL
(DEFUN SBCL-OBJDUMP (SEQ &OPTIONAL LEN)
  "READS A SEQUENCE OF BYTES, INTERPRETS THEM AS MACHINE-CODE
INSTRUCTIONS, AND RETURNS THEIR DISASSEMBLY AS A STRING. SORT OF LIKE
AN IN-HOUSE OBJDUMP."
  (WITH-OUTPUT-TO-STRING (*STANDARD-OUTPUT*)
    (LET ((SAP (SAPIFY SEQ)))
      (SB-SYS:WITH-PINNED-OBJECTS (SAP)
        (SB-DISASSEM:DISASSEMBLE-MEMORY SAP (OR LEN (LENGTH SEQ)))))))

(DEFUN OBJDUMP (SEQ &OPTIONAL LEN)
  (WITH-OUTPUT-TO-STRING (*STANDARD-OUTPUT*)
    (WITH-FOREIGN-POINTER (PTR (LENGTH SEQ) SIZE)
      (LOOP FOR BYTE IN SEQ
         FOR I BELOW SIZE DO
           (SETF (MEM-REF PTR :UNSIGNED-CHAR I) BYTE))
      (SB-DISASSEM:DISASSEMBLE-MEMORY PTR (OR LEN SIZE)))))

(EXPORT 'CHARACTERS)
(DEFUN CHARACTERS (SEQ)
  "PRINTS EVERY HUMAN-READABLE CHARACTER IN THE ORDER IN WHICH IT APPEARS.
PRINTS . FOR UNREADABLE CHARACTERS."
  (COERCE
   (LOOP FOR BYTE IN SEQ COLLECT
        (IF (AND (>= BYTE #X20) (< BYTE #X7F)) (CODE-CHAR BYTE) #\.)) 'STRING))

(EXPORT 'STRINGS)
(DEFUN STRINGS (SEQ &OPTIONAL (MINLEN 3))
  "ESSENTIALLY THE SAME AS THE UNIX UTILITY."
  (LET ((STRS)
        (TMP))
    (LOOP FOR BYTE IN SEQ DO
         (COND ((AND (>= BYTE #X20) (< BYTE #X7F))
                (PUSH (CODE-CHAR BYTE) TMP))
               ((>= (LENGTH TMP) MINLEN)
                (PUSH (COERCE (REVERSE TMP) 'STRING) STRS)
                (SETF TMP NIL))
               (:DEFAULT (SETF TMP NIL))))
    (REVERSE STRS)))

(EXPORT 'LOAD-BIN)
(DEFUN LOAD-BIN (PATH)
  ;; THIS CAN'T POSSIBLY BE THE BEST WAY TO READ IN A BINARY FILE, BUT IT WORKS.
  (WITH-OPEN-FILE (STREAM PATH :DIRECTION :INPUT :ELEMENT-TYPE '(UNSIGNED-BYTE 8))
    (LET ((BYTES NIL))
      (LOOP WHILE (CAR (PUSH (READ-BYTE STREAM NIL NIL) BYTES)))
      (REVERSE (CDR BYTES)))))


(DEFUN SUBUPTO (SEQ UPTO)
  (SUBSEQ SEQ 0 (MIN UPTO (LENGTH SEQ))))


;; NOTE THAT GADGETS% HAS ALMOST EXACTLY THE SAME STRUCTURE AS STRINGS
;; IS THERE SOME COMMON IDIOM HERE THAT WE COULD ABSTRACT INTO A MACRO?
;; OR WOULD THAT JUST MAKE IT MORE COMPLICATED?
(DEFPARAMETER *X86-RET* '(#XC3))

(EXPORT 'RETP)
(DEFUN RETP (BYTE)
  (MEMBER BYTE *RET*))

(DEFPARAMETER *AVOID-INSTS*
  '(#X5D ;; POP RBP
    ))

(DEFUN GADGETS% (BYTES &OPTIONAL (MAXIMUM-GADGET-LENGTH))
  (LET ((GADGETS)
        (MAXLEN (OR MAXIMUM-GADGET-LENGTH (LENGTH BYTES)))
        (TMP))
    (LOOP FOR BYTE IN BYTES DO
         (PUSH BYTE TMP)
         (WHEN (RETP BYTE)
           (PUSH (REVERSE (SUBUPTO TMP MAXLEN)) GADGETS)
           (SETF TMP NIL)))
    (REVERSE GADGETS)))


#+SBCL
(DEFUN GADGETS-FROM-FILE (PATH &OPTIONAL (MAXIMUM-GADGET-LENGTH 32))
   (LOOP FOR GADGET IN (GADGETS%  (LOAD-BIN PATH) MAXIMUM-GADGET-LENGTH) DO
        (FORMAT T "~%; ****************************************************
~A~%" (OBJDUMP GADGET))))

(EXPORT 'HEXIFY)
(DEFUN HEXIFY ()
  (SETQ *PRINT-BASE* (IF (= #X10 *PRINT-BASE*) #XA #X10))
  (SETQ *READ-BASE* (IF (= #X10 *READ-BASE*) #XA #X10))
  (FORMAT T "SETTING *PRINT-BASE* AND *READ-BASE* TO #X~X, #X~X...~%"
          *PRINT-BASE* *READ-BASE*))
        
;; FINDING GADGETS:
;;
;; GADGETS TO AVOID:
;; * GADGETS ENDING WITH LEAVE, FOLLOWED BY RET. LEAVE PERFORMS A POP EBP.
;; * POP EBP.
;; -- WE DON'T WANT TO MESS UP OUR STACK FRAME (PROBABLY)

;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
;; MUCKING AROUND AT THE OBJECT LEVEL MEANS WE NEED TO HANDLE SIGNALS
;; WHEN SOMETHING BREAKS
;; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

;; THIS BIT HERE IS FROM ROSETTA CODE

(DEFVAR *SIGINT*   2)
(DEFVAR *SIGSEGV* 11)

(DEFMACRO SET-SIGNAL-HANDLER (SIGNO &BODY BODY)
  (LET ((HANDLER (GENSYM "HANDLER")))
    `(PROGN
      (CFFI:DEFCALLBACK ,HANDLER :VOID ((SIGNO :INT))
        (DECLARE (IGNORE SIGNO))
        ,@BODY)
      (CFFI:FOREIGN-FUNCALL "SIGNAL" :INT ,SIGNO :POINTER
                            (CFFI:CALLBACK ,HANDLER)))))

;; ----------------------------------------------------------------------



;; (DEFVAR *INITIAL* (GET-INTERNAL-REAL-TIME))

;; (SET-SIGNAL-HANDLER *SIGINT*
;;   (FORMAT T "RAN FOR ~A SECONDS~&" (/ (- (GET-INTERNAL-REAL-TIME) *INITIAL*)
;;                                       INTERNAL-TIME-UNITS-PER-SECOND)))
  ;;  (QUIT))

;; (LET ((I 0))
;;   (LOOP DO
;;        (FORMAT T "~A~&" (INCF I))
;;        (SLEEP 0.5)))






;;; --- NOW SOME MORE PORTABLE FUNCTIONS: WILL DEFINITELY WORK
;;; --- ON CCL, AT THE VERY LEAST.

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


(defparameter *x86_64-machine-code-suffix*
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

(defun chunky-print (opseq)
            (loop for i on opseq by #'cddddr do
                 (format t "~2,'0X~2,'0X~2,'0X~2,'0X~%" 
                         (car i)
                         (cadr i)
                         (caddr i)
                         (cadddr i))))


;; handy if you cut and paste in a block of machine code
;; from objdump, and want to get the instructions back in
;; order.

(defun swap-at (list i j)
            (let ((tmp (elt list i)))
              (setf (elt list i) (elt list j)
                    (elt list j) tmp)))

(defun flip-words (list)
            (loop for word on list by #'cddddr do
                 (swap-at word 0 3)
                 (swap-at word 1 2)))

(defparameter *reg-count* 18) ;; machine dependent
(defun hatch-code (code)
  (with-foreign-pointer (ptr (length code) size)
    (loop for byte in code
       for i below size do
         (setf (mem-ref ptr :unsigned-char i) byte))
    (let ((registers (foreign-funcall "hatch_code" :pointer ptr :pointer))
          (rlist ()))
      (loop for i below *reg-count* do
           (push (mem-ref registers :long i) rlist))
      rlist)))

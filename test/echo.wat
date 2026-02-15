;; echo.wat - copies input to output verbatim
;;
;; Contract:
;;   Host writes input at 0x10000, calls run(0x10000, len)
;;   run returns pointer to [output_len:u32 LE][output_bytes...]
;;   We write the output header at 0x20000.

(module
  (memory (export "memory") 3)  ;; 3 pages = 192KB

  (func (export "run") (param $input_ptr i32) (param $input_len i32) (result i32)
    ;; Write output length at 0x20000
    (i32.store (i32.const 0x20000) (local.get $input_len))

    ;; Copy input bytes to 0x20004
    (memory.copy
      (i32.const 0x20004)        ;; dest
      (local.get $input_ptr)     ;; src
      (local.get $input_len)     ;; len
    )

    ;; Return pointer to output header
    (i32.const 0x20000)
  )
)

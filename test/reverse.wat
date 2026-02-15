;; reverse.wat - reverses input bytes
;;
;; Output at 0x20000: [len:u32 LE][reversed bytes...]

(module
  (memory (export "memory") 3)

  (func (export "run") (param $ptr i32) (param $len i32) (result i32)
    (local $i i32)
    (local $end i32)

    ;; Write output length
    (i32.store (i32.const 0x20000) (local.get $len))

    ;; Reverse copy: out[i] = in[len-1-i]
    (local.set $i (i32.const 0))
    (block $done
      (loop $loop
        (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
        (i32.store8
          (i32.add (i32.const 0x20004) (local.get $i))
          (i32.load8_u
            (i32.add
              (local.get $ptr)
              (i32.sub (i32.sub (local.get $len) (i32.const 1)) (local.get $i))
            )
          )
        )
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $loop)
      )
    )

    (i32.const 0x20000)
  )
)

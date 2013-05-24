.origin 0
.entrypoint start

start:
      
again:
        // led on
        set     r30.t5

        ldi     r0.w0, 100000000 & 0xffff
        ldi     r0.w2, 100000000 >> 16
delay1: sub     r0, r0, 1
        qbne    delay1, r0, 0

        // led off
        clr     r30.t5

        ldi     r0.w0, 100000000 & 0xffff
        ldi     r0.w2, 100000000 >> 16
delay2: sub     r0, r0, 1
        qbne    delay2, r0, 0

        qba     again
        
    HALT

%ifdef CONFIG
{
  "RegData": {
    "XMM0": ["0x2B359F68F27F9CA4", "0x49506A0243EA5B6B"],
    "XMM1": ["0xFB09DC021D842539", "0x320B6A19978511DC"],
    "XMM2": ["0x8CE74CF2A6466E87", "0x95C3EC97D84A904D"],
    "XMM3": ["0xFEEA1913635A7B0C", "0xB4FB4C66908839B0"],
    "XMM4": ["0x8D305A88A8F64332", "0x340737E0A2983131"],
    "XMM5": ["0x3424B5E524B5E434", "0x01EB848BEB848A01"]
  },
  "HostFeatures": ["AES"],
  "Mode": "32BIT"
}
%endif

; 32-BIT MODE AES-NI coverage: aesenc/aesenclast/aesdec/aesdeclast/aesimc/
; aeskeygenassist. The 64-bit suite covers these (H0F38/66_DC..DF etc) but
; there was NO 32-bit AES test at all -- and the Steam client (the biggest
; AES consumer we have) is a 32-bit process. This targets the PPC64LE JIT's
; vcipher/vcipherlast/vncipher/vncipherlast/vsbox lowerings (see
; aes-hw-commit-stranded / vsx-low-bank-dw1-volatile: the vs15 pinned-mask
; regression broke ONLY the 32-bit Steam AESNI path while every 64-bit test
; passed, so 32-bit-mode coverage is not redundant with the 64-bit files).
;
; All expected values are FIPS-197 vectors (AES-128, Appendix A/B):
;   key       = 2b7e151628aed2a6abf7158809cf4f3c  (App A.1)
;   plaintext = 3243f6a8885a308d313198a2e0370734  (App B)
; Derivations (verified against the published FIPS-197 round traces by a
; Python model that also reproduces the existing suite's 66_DC.asm values):
;
; XMM0 aesenc: round-1 input  = pt ^ rk0 = 193de3bea0f4e22b9ac68d2ae9f84808
;              rk1            = a0fafe1788542cb123a339392a6c7605
;              aesenc(in,rk1) = a49c7ff2689f352b6b5bea43026a5049
;              (= FIPS-197 App B "Start of Round 2" state)
; XMM1 aesenclast: round-9 output = eb40f21e592e38848ba113e71bc342d2
;              rk10           = d014f9a8c9ee2589e13f0cc8b6630ca6
;              aesenclast     = 3925841d02dc09fbdc118597196a0b32
;              (= FIPS-197 App B ciphertext)
; XMM3 aesimc: rk9 = ac7766f319fadc2128d12941575c006e
;              aesimc(rk9) = InvMixColumns(rk9) -- the Equivalent Inverse
;              Cipher round key. Value cross-checked by running the full
;              10-round EIC decryption in the model and recovering the
;              FIPS-197 plaintext.
; XMM2 aesdec: first EIC decrypt round: state = ct ^ rk10 =
;              e9317db5cb322c723d2e895faf090794, key = aesimc(rk9) (XMM3,
;              chained through the actual aesimc instruction result).
; XMM4 aesdeclast: last EIC decrypt round input (after the nine aesdec
;              rounds) = d4bf5d30e0b452aeb84111f11e2798e5, key = rk0 = key.
;              Result must be the FIPS-197 plaintext -- so XMM2/XMM3/XMM4
;              jointly re-derive a FIPS-published value through the inverse
;              path.
; XMM5 aeskeygenassist(key, 0x01): per SDM (AESKEYGENASSIST):
;              dw0 = SubWord(X1),           dw1 = RotWord(SubWord(X1)) ^ 1
;              dw2 = SubWord(X3),           dw3 = RotWord(SubWord(X3)) ^ 1
;              X3 (w3 of the key, LE dword 0x3c4fcf09): dw3 = 0x01eb848b,
;              which byte-reversed is 8b84eb01 = the FIPS-197 App A.1
;              key-expansion temp "After XOR with Rcon" for w4. Cross-checked.

lea edx, [r1_in]
movups xmm0, [edx]
lea edx, [rk1]
movups xmm7, [edx]
aesenc xmm0, xmm7

lea edx, [r9_out]
movups xmm1, [edx]
lea edx, [rk10]
movups xmm7, [edx]
aesenclast xmm1, xmm7

; aesimc result kept in XMM3 and also consumed by the aesdec below
lea edx, [rk9]
movups xmm3, [edx]
aesimc xmm3, xmm3

lea edx, [d_in]
movups xmm2, [edx]
aesdec xmm2, xmm3

lea edx, [dl_in]
movups xmm4, [edx]
lea edx, [key]
movups xmm7, [edx]
aesdeclast xmm4, xmm7

lea edx, [key]
movups xmm5, [edx]
aeskeygenassist xmm5, xmm5, 0x01

hlt

; FIPS-197 vectors, stored little-endian
r1_in:  dq 0x2BE2F4A0BEE33D19, 0x0848F8E92A8DC69A
rk1:    dq 0xB12C548817FEFAA0, 0x05766C2A3939A323
r9_out: dq 0x84382E591EF240EB, 0xD242C31BE713A18B
rk10:   dq 0x8925EEC9A8F914D0, 0xA60C63B6C80C3FE1
d_in:   dq 0x722C32CBB57D31E9, 0x940709AF5F892E3D
rk9:    dq 0x21DCFA19F36677AC, 0x6E005C574129D128
dl_in:  dq 0xAE52B4E0305DBFD4, 0xE598271EF11141B8
key:    dq 0xA6D2AE2816157E2B, 0x3C4FCF098815F7AB

# mpk

A thin wrapper around Intel MPK, for research purpose: Do not use in production!

Types:

```go
// Pkey represents a protection key
type Pkey int

// PKRU represents a list of access rights to be stored in PKRU register
type PKRU uint32

// Prot represents a protection access right
type Prot uint32

// SysProt represents protection of the page table entries
type SysProt int
```

API:

```go
// PkeyAlloc allocates a new pkey
func PkeyAlloc() (Pkey, error) {}

// PkeyFree frees a pkey previously allocated
func PkeyFree(pkey Pkey) error {}

// PkeyMprotect tags pages within [addr, addr + len -1] with the given pkey.
// Permission on page table can also be update at the same time.
// Note that addr must be aligned to a page boundary.
func PkeyMprotect(addr uintptr, len uint64, sysProt SysProt, pkey Pkey) error {}

// WritePKRU updates the value of the PKRU
func WritePKRU(prot PKRU) {}

// ReadPKRU returns the value of the PKRU
func ReadPKRU() PKRU {}
```

Available constants

```go
// Protections
const (
	ProtRWX Prot = 0b00
	ProtRX  Prot = 0b10
	ProtX   Prot = 0b11

	SysProtRWX SysProt = syscall.PROT_READ | syscall.PROT_WRITE | syscall.PROT_EXEC
	SysProtRX  SysProt = syscall.PROT_READ | syscall.PROT_EXEC
	SysProtRW  SysProt = syscall.PROT_READ | syscall.PROT_WRITE
	SysProtR   SysProt = syscall.PROT_READ
)

// AllRightsPKRU is the default value of the PKRU, that allows everything
const AllRightsPKRU PKRU = 0
```

package cryptus

type KdfConfig struct {
	length     int // bytes do hash (default 32)
	iterations int // t (default 3)
	memory     int // KiB (default 64 MiB)
	threads    int // p (default 2)
}

type KdfOption func(*KdfConfig)

func NewKdfConfig(options ...KdfOption) KdfConfig {
	cfg := KdfConfig{}
	for _, opt := range options {
		opt(&cfg)
	}
	return cfg
}

func WithLength(v int) KdfOption     { return func(c *KdfConfig) { c.length = v } }
func WithIterations(v int) KdfOption { return func(c *KdfConfig) { c.iterations = v } }
func WithMemory(v int) KdfOption     { return func(c *KdfConfig) { c.memory = v } }
func WithThreads(v int) KdfOption    { return func(c *KdfConfig) { c.threads = v } }

func (k KdfConfig) Length() int {
	if k.length > 0 {
		return k.length
	}
	return 32
}

func (k KdfConfig) Iterations() int {
	if k.iterations > 0 {
		return k.iterations
	}
	return 3
}

func (k KdfConfig) Memory() int {
	if k.memory > 0 {
		return k.memory
	}
	return 1024 * 64
}

func (k KdfConfig) Threads() int {
	if k.threads > 0 {
		return k.threads
	}
	return 2
}

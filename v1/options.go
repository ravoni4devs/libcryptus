package cryptus

type KdfConfig struct {
	length     int64
	iterations int64
	memory     int64
	threads    int64
}

type KdfOption func(*KdfConfig)

func NewKdfConfig(options ...KdfOption) KdfConfig {
	config := KdfConfig{}
	for _, opt := range options {
		opt(&config)
	}
	return config
}

func WithLength(val int64) KdfOption {
	return func(c *KdfConfig) {
		c.length = val
	}
}

func WithIterations(val int64) KdfOption {
	return func(c *KdfConfig) {
		c.iterations = val
	}
}

func WithMemory(val int64) KdfOption {
	return func(c *KdfConfig) {
		c.memory = val
	}
}

func WithThreads(val int64) KdfOption {
	return func(c *KdfConfig) {
		c.threads = val
	}
}

func (k KdfConfig) Length() int64 {
	if k.length > 0 {
		return k.length
	}
	return 16
}

func (k KdfConfig) Iterations() int64 {
	if k.iterations > 0 {
		return k.iterations
	}
	return 3
}

func (k KdfConfig) Memory() int64 {
	if k.memory > 0 {
		return k.memory
	}
	return 1024 * 64
}

func (k KdfConfig) Threads() int64 {
	if k.threads > 0 {
		return k.threads
	}
	return 2
}

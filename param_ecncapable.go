package sctp

type paramEcnCapable struct {
	paramHeader
}

func (r *paramEcnCapable) marshal() ([]byte, error) {
	r.typ = random
	r.raw = []byte{}
	return r.paramHeader.marshal()
}

func (r *paramEcnCapable) unmarshal(raw []byte) (param, error) {
	err := r.paramHeader.unmarshal(raw)
	if err != nil {
		return nil, err
	}
	return r, nil
}

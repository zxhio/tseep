package packet

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

var globalLayerPools map[gopacket.LayerType]*sync.Pool

func addLayerPool[T any](layerType gopacket.LayerType) {
	_, ok := globalLayerPools[layerType]
	if ok {
		return
	}
	globalLayerPools[layerType] = &sync.Pool{
		New: func() any {
			var v T
			return &v
		},
	}
}

func init() {
	globalLayerPools = make(map[gopacket.LayerType]*sync.Pool)
	addLayerPool[layers.Ethernet](layers.LayerTypeEthernet)
	addLayerPool[layers.ARP](layers.LayerTypeARP)
	addLayerPool[layers.Dot1Q](layers.LayerTypeDot1Q)
	addLayerPool[layers.IPv4](layers.LayerTypeIPv4)
	addLayerPool[layers.TCP](layers.LayerTypeTCP)
	addLayerPool[layers.ICMPv4](layers.LayerTypeICMPv4)
	addLayerPool[layers.UDP](layers.LayerTypeUDP)
	addLayerPool[layers.VXLAN](layers.LayerTypeVXLAN)
}

type LayersDecodePostHook interface {
	OnEthernet(DecodingLayer)
	OnARP(DecodingLayer)
	OnVLAN(DecodingLayer)
	OnIPv4(DecodingLayer)
	OnTCP(DecodingLayer)
	OnICMP(DecodingLayer)
	OnUDP(DecodingLayer)
	OnVXLAN(DecodingLayer)
}

type EmptyLayersDecodePostHook struct{}

func (EmptyLayersDecodePostHook) OnEthernet(DecodingLayer) {}
func (EmptyLayersDecodePostHook) OnARP(DecodingLayer)      {}
func (EmptyLayersDecodePostHook) OnVLAN(DecodingLayer)     {}
func (EmptyLayersDecodePostHook) OnIPv4(DecodingLayer)     {}
func (EmptyLayersDecodePostHook) OnTCP(DecodingLayer)      {}
func (EmptyLayersDecodePostHook) OnICMP(DecodingLayer)     {}
func (EmptyLayersDecodePostHook) OnUDP(DecodingLayer)      {}
func (EmptyLayersDecodePostHook) OnVXLAN(DecodingLayer)    {}

type LayerDecodePostFn func(DecodingLayer)
type LayersDecodePostFn func([]DecodingLayer)

type decodeOpts struct {
	layersHooks    map[gopacket.LayerType][]LayerDecodePostFn
	completedHooks []LayersDecodePostFn
}

type DecodeOpt func(*decodeOpts)

// WithLayerDecodedHook registers a hook for a specific layer type
func WithLayerDecodedHook(layerType gopacket.LayerType, hook LayerDecodePostFn) DecodeOpt {
	return func(do *decodeOpts) {
		hooks, ok := do.layersHooks[layerType]
		if !ok {
			hooks = []LayerDecodePostFn{}
		}
		hooks = append(hooks, hook)
		do.layersHooks[layerType] = hooks
	}
}

// WithLayersDecodedHook registers hooks for multiple layers
func WithLayersDecodedHook(layersHook LayersDecodePostHook) DecodeOpt {
	return func(do *decodeOpts) {
		WithLayerDecodedHook(layers.LayerTypeEthernet, layersHook.OnEthernet)(do)
		WithLayerDecodedHook(layers.LayerTypeARP, layersHook.OnARP)(do)
		WithLayerDecodedHook(layers.LayerTypeDot1Q, layersHook.OnVLAN)(do)
		WithLayerDecodedHook(layers.LayerTypeIPv4, layersHook.OnIPv4)(do)
		WithLayerDecodedHook(layers.LayerTypeTCP, layersHook.OnTCP)(do)
		WithLayerDecodedHook(layers.LayerTypeICMPv4, layersHook.OnICMP)(do)
		WithLayerDecodedHook(layers.LayerTypeUDP, layersHook.OnUDP)(do)
		WithLayerDecodedHook(layers.LayerTypeVXLAN, layersHook.OnVXLAN)(do)
	}
}

func WithLayersDecodedHooks(layersHooks []LayersDecodePostHook) DecodeOpt {
	return func(do *decodeOpts) {
		for _, layersHook := range layersHooks {
			WithLayersDecodedHook(layersHook)(do)
		}
	}
}

// WithCompletedHook registers a hook that will be called after all layers are decoded
func WithCompletedHook(hook LayersDecodePostFn) DecodeOpt {
	return func(do *decodeOpts) {
		do.completedHooks = append(do.completedHooks, hook)
	}
}

// Decoder defines the interface for decoding layers
type Decoder interface {
	Decode(data []byte, oob []byte) error
}

// DecodingLayer extends gopacket.DecodingLayer and includes layer type info
type DecodingLayer interface {
	gopacket.DecodingLayer
	LayerType() gopacket.LayerType
}

type LayersDecoder struct {
	opts       decodeOpts
	layers     []DecodingLayer
	layerPools map[gopacket.LayerType]*sync.Pool
}

func NewLayersDecoder(opts ...DecodeOpt) *LayersDecoder {
	o := decodeOpts{layersHooks: make(map[gopacket.LayerType][]LayerDecodePostFn)}
	for _, opt := range opts {
		opt(&o)
	}
	return &LayersDecoder{opts: o, layerPools: globalLayerPools}
}

func (d *LayersDecoder) Decode(data []byte, oob []byte) error {
	defer func() {
		for _, layer := range d.layers {
			pool, ok := d.layerPools[layer.LayerType()]
			if !ok {
				continue
			}
			pool.Put(layer)
		}
	}()
	d.layers = d.layers[:0]
	return d.decode(data, oob)
}

func (d *LayersDecoder) decode(data []byte, oob []byte) error {
	var (
		currLayerType    gopacket.LayerType
		currLayerPayload []byte
	)

	// First, handle the Ethernet layer separately for the following reasons:
	//    - Ensure the validity of the data early.
	//    - If VLAN layer is present, it needs to be constructed from auxiliary data (oob), which may alter internal state.
	pool, ok := d.layerPools[layers.LayerTypeEthernet]
	if !ok {
		return fmt.Errorf("1st layer is not ethernet")
	}
	ethernetLayer, err := d.decodeLayerAndCallHooks(pool, data)
	if err != nil {
		return err
	}
	currLayerType = ethernetLayer.NextLayerType()
	currLayerPayload = ethernetLayer.LayerPayload()

	// If the Ethernet layer contains VLAN, construct the VLAN layer from auxiliary data (oob)
	if len(oob) != 0 && ethernetLayer.NextLayerType() == layers.LayerTypeIPv4 {
		d.buildVLANLayerAndCallHooks(ethernetLayer.(*layers.Ethernet), oob)
	}

	// General protocol layer decoding
	for len(currLayerPayload) > 0 {
		pool, ok = d.layerPools[currLayerType]
		if !ok {
			break
		}
		nextLayer, err := d.decodeLayerAndCallHooks(pool, currLayerPayload)
		if err != nil {
			return err
		}
		currLayerType = nextLayer.NextLayerType()
		currLayerPayload = nextLayer.LayerPayload()
	}

	for _, hook := range d.opts.completedHooks {
		hook(d.layers)
	}
	return nil
}

func (d *LayersDecoder) decodeLayerAndCallHooks(pool *sync.Pool, data []byte) (DecodingLayer, error) {
	layer := pool.Get().(DecodingLayer)
	err := layer.DecodeFromBytes(data, gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, err
	}
	d.layers = append(d.layers, layer)

	d.callLayerHooks(layer)
	return layer, nil
}

func (d *LayersDecoder) buildVLANLayerAndCallHooks(ether *layers.Ethernet, oob []byte) error {
	vlanId, err := decodeVlanIdByAuxData(oob)
	if err != nil {
		return err
	}
	if vlanId == 0 {
		return nil
	}

	pool, ok := d.layerPools[layers.LayerTypeDot1Q]
	if !ok {
		return nil
	}
	vlan := pool.Get().(*layers.Dot1Q)
	vlan.VLANIdentifier = vlanId
	vlan.Type = layers.EthernetTypeIPv4

	// Fix ethernet type
	ether.EthernetType = layers.EthernetTypeDot1Q
	d.layers = append(d.layers, vlan)

	d.callLayerHooks(vlan)
	return nil
}

func (d *LayersDecoder) callLayerHooks(layer DecodingLayer) {
	hooks, ok := d.opts.layersHooks[layer.LayerType()]
	if !ok {
		return
	}
	for _, hook := range hooks {
		hook(layer)
	}
}

func decodeVlanIdByAuxData(oob []byte) (uint16, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, err
	}

	for _, m := range msgs {
		// Check for relevant level and type for VLAN data
		if m.Header.Level == syscall.SOL_PACKET && m.Header.Type == 8 && len(m.Data) >= 20 {
			auxdata := unix.TpacketAuxdata{
				Status:   binary.LittleEndian.Uint32(m.Data[0:4]),
				Vlan_tci: binary.LittleEndian.Uint16(m.Data[16:18]),
			}
			if auxdata.Status&unix.TP_STATUS_VLAN_VALID != 0 {
				return auxdata.Vlan_tci, nil
			}
		}
	}
	return 0, nil
}

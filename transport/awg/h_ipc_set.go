package awg

import "os"

// IpcSet applies UAPI lines to the running device (update_only for a peer's own values). //H
func (d *Device) IpcSet(config string) error {
	if d.awgDevice == nil {
		return os.ErrInvalid
	}
	return d.awgDevice.IpcSet(config)
}

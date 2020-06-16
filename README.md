# This is an FPGA driver framework on linux.

An FPGA consists of multiple IPs.
Certain features without clear boundaries can also be abstracted into IP.
In some complex FPGA architecture, there may be an FPGA cascade structure.

The framework is implemented according to the Linux device driver model.

A virtual bus type `fpga_bus_type` is implemented.
And FPGA is instantiated as a controller of this bus type.
And IP on FPGA is instantiated as a bus slave device.

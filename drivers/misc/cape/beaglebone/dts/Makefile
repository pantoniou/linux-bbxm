# unconditionally for now */

# Rule to build device tree plugin blobs
$(obj)/%.dtbo: $(src)/dts/%.dts FORCE
	$(call if_changed_dep,dtco)

$(obj)/dtbos: $(addprefix $(obj)/, $(dtbo-y))

extra-y += cape-bone-2g-emmc1.dtbo \
	   cape-bone-dvi-00A0.dtbo cape-bone-dvi-00A1.dtbo


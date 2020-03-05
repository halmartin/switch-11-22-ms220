SECTIONS
{
	.text : {
		*(.text*)
	}

	__end = .;

	/DISCARD/ : {
		*(.reginfo)
	}
}

OUTDIR = ../ebin
SOURCES = $(wildcard *.erl)
BEAMS = $(addprefix $(OUTDIR)/,LDAP.beam $(SOURCES:.erl=.beam))
ASN_FLAGS = -bber_bin +optimize +driver
ASN_OUT = $(addprefix $(OUTDIR)/,LDAP.erl LDAP.asn1db LDAP.hrl)
EFLAGS += -I $(OUTDIR) +warn_missing_spec

all: 	$(BEAMS)

$(OUTDIR)/%.beam: %.erl
	erlc -W $(EFLAGS) -o $(OUTDIR) $<

$(OUTDIR)/LDAP.beam: LDAP.asn1
	erlc $(ASN_FLAGS) -o $(OUTDIR) $<

clean:
	-rm -f $(BEAMS) $(ASN_OUT)

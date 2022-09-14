import json
f = open('json.txt')
data = json.load(f)
f.close()
mbc = []

for rulz in data['rules']:
	print("\nRule match:", rulz)
	try:
		if data['rules'][rulz]['meta']['mbc'][0]['behavior'] not in mbc:
			mbc.append(data['rules'][rulz]['meta']['mbc'][0]['behavior'])
	except Exception:
		pass
	try:
		scope = data['rules'][rulz]['meta']['scope']
	except:
		scope  = "N/A"
	try:
		offset = hex(data['rules'][rulz]['matches'][0][0]['value'])
	except:
		offset = "N/A"
	try:
		tactic = data['rules'][rulz]['meta']['attack'][0]['tactic']
	except:
		tactic = "N/A"
	try:
		tech = data['rules'][rulz]['meta']['attack'][0]['technique']
	except:
		tech = "N/A"
	try:
		subtech = data['rules'][rulz]['meta']['attack'][0]['subtechnique']
	except:
		subtech = "N/A"
	try:
		mitre = data['rules'][rulz]['meta']['attack'][0]['id']
	except:
		mitre = "N/A"
	
	print("\tScope:", scope)
	print("\tMatches:", offset)
	print("\tTactic:", tactic)
	print("\tTechnique:", tech)
	print("\tSubtechnique:", subtech)
	print("\tMITRE:", mitre)
	
print("\nMalware Behavior Catalog:")

for behave in mbc:
	print("\t", behave)

"""
Opens a textfile and writes its contents to an htmlfile with appropriate formatting
"""

def text2html(textfile, htmlfile):
	with open(textfile, 'r') as tfile:
		with open(htmlfile, 'w+') as hfile:
			hfile.write('''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd"><html>

			<head>
				<meta http-equiv="Content-Type"
					  content="text/html; charset=ISO-8859-1" />
				<title></title>
				<style type="text/css">
					table.diff {font-family:Courier; border:medium;}
					.diff_header {background-color:#e0e0e0}
					td.diff_header {text-align:right}
					.diff_next {background-color:#c0c0c0}
					.diff_add {background-color:#aaffaa}
					.diff_chg {background-color:#ffff77}
					.diff_sub {background-color:#ffaaaa}
				</style>
			</head>

			<body>
				
				<table class="diff" id="difflib_chg_to0__top"
					   cellspacing="0" cellpadding="0" rules="groups" >
					<colgroup></colgroup> <colgroup></colgroup> <colgroup></colgroup> 
					<thead><tr><th class="diff_next"><br /></th><th colspan="2" class="diff_header">''' +
					textfile + "</th></thead><tbody>")
			count = 1
			for line in tfile:
				hfile.write('<tr><td class="diff_next"></td><td class="diff_header" id="from0_'+str(count)+'">'+str(count)+'</td><td nowrap="nowrap">'+line+'</td>')
				count = count + 1
			hfile.write('''</tbody>
				</table>
			</body>

			</html>''')

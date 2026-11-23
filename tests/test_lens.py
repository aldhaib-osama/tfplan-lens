import unittest
import tfplan_lens as t


def plan(kind, after, unknown=None, actions=None):
    return {'format_version': '1.2', 'resource_changes': [{'address': 'fictional.demo',
        'type': kind, 'change': {'actions': actions or ['create'], 'after': after,
        'after_unknown': unknown or {}}}]}


def sg(cidr='0.0.0.0/0', port=22, protocol='tcp'):
    return {'ingress': [{'cidr_blocks': [cidr], 'ipv6_cidr_blocks': [],
            'from_port': port, 'to_port': port, 'protocol': protocol}]}


class LensTests(unittest.TestCase):
    def test_public_ssh(self):
        self.assertEqual(t.scan(plan('aws_security_group', sg()))['findings'][0]['rule'], 'SG_PUBLIC_ADMIN')
    def test_ipv6_rdp(self):
        self.assertTrue(t.scan(plan('aws_security_group', sg('::/0',3389)))['findings'])
    def test_private_ssh(self):
        self.assertFalse(t.scan(plan('aws_security_group', sg('10.0.0.0/8')))['findings'])
    def test_all_protocols(self):
        self.assertTrue(t.scan(plan('aws_security_group', sg(port=0,protocol='-1')))['findings'])
    def test_noncanonical_public_cidr(self):
        self.assertTrue(t.public_network('1.2.3.4/0'))
    def test_unknown_not_clean(self):
        r=t.scan(plan('aws_db_instance',{}, {'storage_encrypted':True}))
        self.assertIn('REVIEW_UNKNOWN',[f['rule'] for f in r['findings']])
    def test_delete_skipped(self):
        self.assertFalse(t.scan(plan('aws_security_group',sg(),actions=['delete']))['findings'])
    def test_secure_db(self):
        self.assertFalse(t.scan(plan('aws_db_instance', {'publicly_accessible':False,'storage_encrypted':True}))['findings'])
    def test_db_findings(self):
        self.assertEqual(len(t.scan(plan('aws_db_instance',{'publicly_accessible':True,'storage_encrypted':False}))['findings']),2)
    def test_s3_disabled(self):
        r=t.scan(plan('aws_s3_bucket_public_access_block',dict.fromkeys(
            ['block_public_acls','block_public_policy','ignore_public_acls','restrict_public_buckets'],False)))
        self.assertEqual(r['findings'][0]['rule'],'S3_BLOCK_DISABLED')
    def test_bad_cidr_rejected(self):
        with self.assertRaises(ValueError): t.scan(plan('aws_security_group',sg('broken')))
    def test_bad_cidr_list_rejected(self):
        with self.assertRaises(ValueError):
            t.scan(plan('aws_security_group',{'ingress':[{'cidr_blocks':None}]}))
    def test_bad_format(self):
        with self.assertRaises(ValueError): t.scan({'format_version':'9.0','resource_changes':[]})
    def test_state_not_plan(self):
        with self.assertRaises(ValueError): t.scan({'format_version':'1.0','values':{}})
    def test_unknown_resource_counted(self):
        self.assertEqual(t.scan(plan('unsupported_type',{}))['skipped_resources'],1)


if __name__ == '__main__': unittest.main()

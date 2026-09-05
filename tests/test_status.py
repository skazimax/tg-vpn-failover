import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('vpn_status',Path(__file__).resolve().parents[1]/'lib/status.py')
status=importlib.util.module_from_spec(spec);spec.loader.exec_module(status)

class StatusTest(unittest.TestCase):
    def setUp(self):
        self.health={'checked_at':1000,'active':'adguard','paths':{n:{'core':True,'api':True,'checked_at':1000} for n in ['shared','adguard','vless']}}
        self.units={n:'active' for n in ['shared','adguard','vless','mtg','timer']};self.units['result']='success'
    def render(self,now=1010):
        return status.render(self.health,'adguard',self.units,True,now,True)
    def test_both_checks_required(self):
        self.assertTrue(self.render().startswith('✅ VPN'))
        self.health['paths']['shared']['api']=False
        self.assertTrue(self.render().startswith('❌ VPN'))
    def test_old_future_check(self):
        for now in [1100,900]: self.assertTrue(self.render(now).startswith('⚠️ VPN'))
    def test_changed_route(self):
        self.health['active']='vless';self.assertTrue(self.render().startswith('⚠️ VPN'))
    def test_active_timer_no_checks(self):
        self.health={};self.assertIn('актуальной проверки нет',self.render())
    def test_failed_process(self):
        self.units['shared']='failed';self.assertTrue(self.render().startswith('❌ VPN'))
    def test_timer_last_failure(self):
        self.units['result']='exit-code';self.assertIn('последнее выполнение завершилось ошибкой',self.render())
    def test_malformed_samples(self):
        for sample in [None,{}, {'checked_at':1000,'core':'yes','api':True}]:
            self.health['paths']['shared']=sample;self.assertTrue(self.render().startswith('⚠️ VPN'))
    def test_per_path_age(self):
        self.health['paths']['shared']['checked_at']=800;self.assertTrue(self.render().startswith('⚠️ VPN'))
    def test_config_route(self):
        self.assertEqual(status.configured_route({'outbounds':[{'tag':'active-upstream','server_port':1081}]}),'vless')
        self.assertIsNone(status.configured_route({'outbounds':[None]}))
    def test_mtproto_explicitly_local(self):
        text=status.render(self.health,'adguard',self.units,True,1010,mtproto=True)
        self.assertIn('локальный порт',text);self.assertNotIn('Telegram',text)

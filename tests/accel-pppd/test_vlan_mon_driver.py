import pytest
import os

# test that vlan_mon kernel module is loaded
@pytest.mark.dependency(name = 'vlan_mon_driver_loaded', scope = 'session')
def test_vlan_mon_kernel_module_loaded():
    assert os.path.isdir("/sys/module/vlan_mon")
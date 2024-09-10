

import zzPluginBase.emuRunFlare as emuRunFlare
import zzPluginBase.emuRun as emuRun


#模拟执行

start = 0x50a30
end = 0x50acc
regName = "X8"

result = emuRunFlare.emu_run_code(start, end, regName)
emuRun.patch_code(start, end, result)
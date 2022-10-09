// description:
// @author renshiwei
// Date: 2022/9/28 19:51

package maputil

import (
	"sync"
)

//CapSyncMap 获取 sync.Map 的容量
func CapSyncMap(syncMap *sync.Map) int {
	count := 0
	syncMap.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// description:
// @author renshiwei
// Date: 2022/9/26 19:46

package util

import (
	"fmt"
	"testing"
	"time"
)

func TestCurrentTime(t *testing.T) {
	fmt.Printf("系统时间：%v\n", time.Now())
	fmt.Printf("UTC时间：%v\n", time.Now().UTC())
	fmt.Printf("东八区当前时间：%v\n", East8Time())
	fmt.Printf("北京时间：%v\n", BeiJingTime())
	fmt.Printf("上海时间：%v\n", ShangHaiTime())
	fmt.Printf("东八区当前时间（格式化）：%s\n", East8TimeDefaultFormat())
}

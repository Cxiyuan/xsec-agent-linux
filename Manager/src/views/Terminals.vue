<template>
  <div class="terminals-container">
    <!-- 左侧：资产分组 -->
    <div class="terminals-sidebar">
      <div class="sidebar-header">
        <span>资产分组</span>
        <div class="header-actions">
          <el-button size="mini" type="text" @click="handleAddGroup">新增</el-button>
          <el-dropdown trigger="click" @command="handleCommand">
            <span class="el-dropdown-link">
              <i class="el-icon-more"></i>
            </span>
            <el-dropdown-menu slot="dropdown">
              <el-dropdown-item command="rename">重命名</el-dropdown-item>
              <el-dropdown-item command="delete">删除</el-dropdown-item>
            </el-dropdown-menu>
          </el-dropdown>
        </div>
      </div>
      <div class="sidebar-content">
        <el-tree
          :data="groupTree"
          :props="treeProps"
          node-key="id"
          default-expand-all
          
          @node-click="handleNodeClick"
        >
          <span slot-scope="{ node, data }" class="tree-node">
            <span class="node-icon">
              <i :class="data.children && data.children.length ? 'el-icon-folder' : 'el-icon-document'"></i>
            </span>
            <span class="node-label">{{ node.label }}</span>
          </span>
        </el-tree>
      </div>
    </div>

    <!-- 右侧：终端列表 -->
    <div class="terminals-main">
      <el-card class="page-card" :body-style="{ padding: '0' }">
        <div slot="header" class="header-row">
          <span>终端列表</span>
          <div>
            <el-input v-model="searchKeyword" placeholder="搜索..." size="small" style="width: 160px; margin-right: 8px;" clearable>
              <i class="el-icon-search" slot="prefix"></i>
            </el-input>
            <el-select v-model="refreshInterval" size="small" style="width: 90px; margin-right: 8px;" @change="startAutoRefresh">
              <el-option label="5秒" :value="5000"></el-option>
              <el-option label="10秒" :value="10000"></el-option>
              <el-option label="15秒" :value="15000"></el-option>
              <el-option label="30秒" :value="30000"></el-option>
              <el-option label="45秒" :value="45000"></el-option>
            </el-select>
            <el-button size="small" type="primary" icon="el-icon-refresh" @click="fetchTerminals">刷新</el-button>
          </div>
        </div>
        <el-table :data="filteredTerminals" v-loading="loading" stripe style="width: 100%">
          <el-table-column prop="asset_name" label="资产名称" width="140">
            <template slot-scope="scope">
              {{ scope.row.asset_name || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="asset_group" label="资产分组" width="120">
            <template slot-scope="scope">
              {{ scope.row.asset_group || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="hostname" label="主机名称"></el-table-column>
          <el-table-column prop="ip" label="IP地址" width="140"></el-table-column>
          <el-table-column prop="mac" label="MAC地址" width="180">
            <template slot-scope="scope">
              {{ scope.row.mac || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="os" label="操作系统" width="120"></el-table-column>
          <el-table-column prop="status" label="状态" width="100">
            <template slot-scope="scope">
              <el-tag :type="scope.row.status === 'online' ? 'success' : 'info'" size="small">
                {{ scope.row.status === 'online' ? '在线' : '离线' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="cpu_percent" label="CPU利用率" width="120">
            <template slot-scope="scope">
              <div class="gauge-cell" :style="{'--pct': (scope.row.cpu_percent || 0) + '%', '--color': getGaugeColor(scope.row.cpu_percent)}">
                <div class="gauge-bar"><div class="gauge-fill"></div></div>
                <span class="gauge-text">{{ scope.row.cpu_percent ? scope.row.cpu_percent.toFixed(1) + '%' : '-' }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column prop="memory_percent" label="内存利用率" width="120">
            <template slot-scope="scope">
              <div class="gauge-cell" :style="{'--pct': (scope.row.memory_percent || 0) + '%', '--color': getGaugeColor(scope.row.memory_percent)}">
                <div class="gauge-bar"><div class="gauge-fill"></div></div>
                <span class="gauge-text">{{ scope.row.memory_percent ? scope.row.memory_percent.toFixed(1) + '%' : '-' }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column prop="disk_percent" label="磁盘利用率" width="120">
            <template slot-scope="scope">
              <div class="gauge-cell" :style="{'--pct': (scope.row.disk_percent || 0) + '%', '--color': getGaugeColor(scope.row.disk_percent)}">
                <div class="gauge-bar"><div class="gauge-fill"></div></div>
                <span class="gauge-text">{{ scope.row.disk_percent ? scope.row.disk_percent.toFixed(1) + '%' : '-' }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column prop="last_seen" label="最后活跃时间" width="160"></el-table-column>
          <el-table-column label="操作" width="200">
            <template slot-scope="scope">
              <el-button type="text" size="small" @click="goDetail(scope.row)">详情</el-button>
              <el-button type="text" size="small" @click="handleEdit(scope.row)">编辑</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>

    <!-- 详情侧边栏 -->
    <el-drawer
      :title="selectedTerminal ? selectedTerminal.hostname : '终端详情'"
      :visible.sync="drawerVisible"
      direction="rtl"
      size="600px"
    >
      <div class="drawer-tabs" v-if="selectedTerminal">
        <el-tabs v-model="activeTab">
          <!-- 硬件详情 -->
          <el-tab-pane label="硬件详情" name="hardware">
            <div class="tab-content">
              <h4>基本信息</h4>
              <el-descriptions :column="1" border size="small">
                <el-descriptions-item label="主机名称">{{ selectedTerminal.hostname || '-' }}</el-descriptions-item>
                <el-descriptions-item label="IP地址">{{ selectedTerminal.ip || '-' }}</el-descriptions-item>
                <el-descriptions-item label="MAC地址">{{ selectedTerminal.mac || '-' }}</el-descriptions-item>
                <el-descriptions-item label="操作系统">{{ selectedTerminal.os }} {{ selectedTerminal.arch || '' }}</el-descriptions-item>
                <el-descriptions-item label="Agent版本">{{ selectedTerminal.version || '-' }}</el-descriptions-item>
              </el-descriptions>

              <h4>硬件信息</h4>
              <el-descriptions :column="1" border size="small">
                <el-descriptions-item label="CPU">{{ terminalDetail.cpu_model || '未知' }}</el-descriptions-item>
                <el-descriptions-item label="CPU核心数">{{ terminalDetail.cpu_cores || '-' }}</el-descriptions-item>
                <el-descriptions-item label="内存总量">{{ formatBytes(terminalDetail.memory_total) }}</el-descriptions-item>
                <el-descriptions-item label="磁盘">{{ terminalDetail.disk_info || '-' }}</el-descriptions-item>
              </el-descriptions>
            </div>
          </el-tab-pane>

          <!-- 暴露面 -->
          <el-tab-pane label="暴露面" name="exposure">
            <div class="tab-content">
              <h4>监听端口</h4>
              <el-table :data="terminalDetail.ports || []" stripe size="small" max-height="400">
                <el-table-column prop="protocol" label="协议" width="80"></el-table-column>
                <el-table-column prop="port" label="端口" width="80"></el-table-column>
                <el-table-column prop="program" label="程序"></el-table-column>
                <el-table-column prop="pid" label="PID" width="80"></el-table-column>
              </el-table>
              <div v-if="!terminalDetail.ports || terminalDetail.ports.length === 0" class="empty-tip">
                暂无监听端口数据
              </div>
            </div>
          </el-tab-pane>

          <!-- 漏洞情况 -->
          <el-tab-pane label="漏洞情况" name="vulns">
            <div class="tab-content">
              <h4>软件漏洞</h4>
              <el-table :data="terminalDetail.vulns || []" stripe size="small" max-height="400">
                <el-table-column prop="cve_id" label="CVE编号" width="140"></el-table-column>
                <el-table-column prop="software" label="软件" width="120"></el-table-column>
                <el-table-column prop="version" label="版本" width="80"></el-table-column>
                <el-table-column prop="severity" label="严重性" width="80">
                  <template slot-scope="scope">
                    <el-tag :type="scope.row.severity === 'high' ? 'danger' : scope.row.severity === 'medium' ? 'warning' : 'info'" size="small">
                      {{ scope.row.severity || '-' }}
                    </el-tag>
                  </template>
                </el-table-column>
                <el-table-column prop="description" label="描述"></el-table-column>
              </el-table>
              <div v-if="!terminalDetail.vulns || terminalDetail.vulns.length === 0" class="empty-tip">
                暂无漏洞数据
              </div>
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-drawer>
  </div>
</template>

<script>
import { getAgentList, getAssetGroups, createAssetGroup, updateAssetGroup, deleteAssetGroup, updateAgentInfo } from '@/utils/api'

export default {
  name: 'Terminals',
  data() {
    return {
      terminals: [],
      loading: false,
      activeGroup: null,
      groupTree: [
        {
          id: 0,
          label: '资产中心',
          children: []
        }
      ],
      treeProps: {
        children: 'children',
        label: 'label'
      },
      groupOptions: [],
      drawerVisible: false,
      drawerTitle: '终端详情',
      selectedTerminal: null,
      activeTab: 'hardware',
      terminalDetail: {},
      refreshInterval: 5000,
      autoRefreshTimer: null,
      searchKeyword: ''
    }
  },
  mounted() {
    this.fetchTerminals()
    this.fetchGroups()
    this._isMounted = true
    this.startAutoRefresh()
  },
  computed: {
    onlineCount() {
      return this.terminals.filter(t => t.status === 'online').length
    },
    offlineCount() {
      return this.terminals.filter(t => t.status !== 'online').length
    },
    filteredTerminals() {
      if (!this.searchKeyword) {
        return this.terminals
      }
      const kw = this.searchKeyword.toLowerCase()
      return this.terminals.filter(t => {
        return (t.asset_name && t.asset_name.toLowerCase().includes(kw)) ||
               (t.asset_group && t.asset_group.toLowerCase().includes(kw)) ||
               (t.hostname && t.hostname.toLowerCase().includes(kw)) ||
               (t.ip && t.ip.toLowerCase().includes(kw))
      })
    }
  },
  mounted() {
    this.fetchTerminals()
    this.fetchGroups()
    this._isMounted = true
  },
  activated() {
    if (this._isMounted && !this._isFetching) {
      this.fetchTerminals()
    }
  },
  beforeDestroy() {
    this._isMounted = false
    if (this.autoRefreshTimer) {
      clearInterval(this.autoRefreshTimer)
    }
  },
  methods: {
    startAutoRefresh() {
      if (this.autoRefreshTimer) {
        clearInterval(this.autoRefreshTimer)
      }
      this.autoRefreshTimer = setInterval(() => {
        if (!this._isFetching) {
          this.fetchTerminals()
        }
      }, this.refreshInterval)
    },
    getGaugeColor(value) {
      if (!value) return '#999'
      if (value < 60) return '#0E9472'
      if (value < 90) return '#FF9B1B'
      return '#A10404'
    },
    fetchTerminals() {
      if (this._isFetching) return
      this._isFetching = true
      this.loading = true
      getAgentList().then(res => {
        if (res && res.data && Array.isArray(res.data)) {
          this.terminals = res.data
        } else if (Array.isArray(res)) {
          this.terminals = res
        } else {
          this.terminals = []
        }
      }).catch(err => {
        console.warn('获取终端列表失败:', err)
      }).finally(() => {
        this.loading = false
        this._isFetching = false
      })
    },
    fetchGroups() {
      getAssetGroups().then(res => {
        if (res && res.data && Array.isArray(res.data)) {
          // 更新分组树
          this.groupTree[0].children = res.data.map(g => ({
            id: g.id,
            label: g.name,
            children: []
          }))
          // 更新下拉选项
          this.groupOptions = res.data.map(g => ({
            id: g.id,
            label: g.name
          }))
        }
      }).catch(err => {
        console.warn('获取分组列表失败:', err)
      })
    },
    handleNodeClick(data) {
      this.activeGroup = data.id
    },
    handleAddGroup() {
      this.$prompt('请输入分组名称', '新增分组', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        inputPattern: /\S+/,
        inputErrorMessage: '分组名称不能为空'
      }).then(({ value }) => {
        createAssetGroup({ name: value }).then(res => {
          if (res && res.code === 0 && res.data) {
            this.groupTree[0].children.push({
              id: res.data.id,
              label: res.data.name,
              children: []
            })
            this.$message.success('分组已创建')
          } else {
            this.$message.error(res.message || '创建失败')
          }
        }).catch(err => {
          this.$message.error('创建分组失败')
        })
      }).catch(() => {})
    },
    handleCommand(command) {
      if (!this.activeGroup || this.activeGroup === 0) {
        this.$message.warning('请先选择一个分组')
        return
      }
      if (command === 'rename') {
        this.handleRename()
      } else if (command === 'delete') {
        this.handleDelete()
      }
    },
    handleRename() {
      const node = this.findNode(this.groupTree, this.activeGroup)
      if (!node || this.activeGroup === 0) return
      this.$prompt('请输入新的分组名称', '重命名分组', {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        inputValue: node.label,
        inputPattern: /\S+/,
        inputErrorMessage: '分组名称不能为空'
      }).then(({ value }) => {
        updateAssetGroup(this.activeGroup, { name: value }).then(res => {
          if (res && res.code === 0) {
            node.label = value
            this.$message.success('分组已重命名')
          } else {
            this.$message.error(res.message || '重命名失败')
          }
        }).catch(err => {
          this.$message.error('重命名分组失败')
        })
      }).catch(() => {})
    },
    handleDelete() {
      if (this.activeGroup === 0) return
      this.$confirm('确定删除该分组？', '删除确认').then(() => {
        deleteAssetGroup(this.activeGroup).then(res => {
          if (res && res.code === 0) {
            this.removeNode(this.groupTree, this.activeGroup)
            this.activeGroup = null
            this.$message.success('分组已删除')
          } else {
            this.$message.error(res.message || '删除失败')
          }
        }).catch(err => {
          this.$message.error('删除分组失败')
        })
      }).catch(() => {})
    },
    findNode(tree, id) {
      for (const node of tree) {
        if (node.id === id) return node
        if (node.children) {
          const found = this.findNode(node.children, id)
          if (found) return found
        }
      }
      return null
    },
    removeNode(tree, id) {
      for (let i = 0; i < tree.length; i++) {
        if (tree[i].id === id) {
          tree.splice(i, 1)
          return true
        }
        if (tree[i].children) {
          if (this.removeNode(tree[i].children, id)) return true
        }
      }
      return false
    },
    goDetail(row) {
      this.selectedTerminal = { ...row }
      this.activeTab = 'hardware'
      this.terminalDetail = {}
      this.drawerVisible = true
      // TODO: 后续调用 API 获取详细硬件信息、暴露面、漏洞数据
      // 目前使用 Agent 上报的 environment_info 解析
      try {
        if (row.environment_info) {
          const env = typeof row.environment_info === 'string' ? JSON.parse(row.environment_info) : row.environment_info
          this.terminalDetail = {
            cpu_model: env.cpu_model || '-',
            cpu_cores: env.cpu_cores || '-',
            memory_total: env.memory_total || 0,
            disk_info: this.parseDiskInfo(row.disk_partitions),
            ports: env.ports || [],
            vulns: []
          }
        }
      } catch (e) {
        console.warn('解析环境信息失败:', e)
      }
    },
    parseDiskInfo(partitions) {
      if (!partitions) return '-'
      try {
        const parts = typeof partitions === 'string' ? JSON.parse(partitions) : partitions
        if (Array.isArray(parts) && parts.length > 0) {
          return parts.map(p => `${p.mount || p.name}: ${p.total ? this.formatBytes(p.total) : 'N/A'}`).join(', ')
        }
      } catch (e) {}
      return '-'
    },
    formatBytes(bytes) {
      if (!bytes || bytes === 0) return '-'
      const units = ['B', 'KB', 'MB', 'GB', 'TB']
      let i = 0
      while (bytes >= 1024 && i < units.length - 1) {
        bytes /= 1024
        i++
      }
      return bytes.toFixed(2) + ' ' + units[i]
    },
    saveEdit() {
      updateAgentInfo(this.selectedTerminal.id, {
        asset_group: this.selectedTerminal.asset_group || '',
        asset_name: this.selectedTerminal.asset_name || ''
      }).then(res => {
        if (res && res.code === 0) {
          this.$message.success('保存成功')
          this.drawerVisible = false
          this.fetchTerminals()
        } else {
          this.$message.error(res.message || '保存失败')
        }
      }).catch(err => {
        this.$message.error('保存失败')
      })
    },
    formatTime(time) {
      if (!time) return '-'
      const d = new Date(time)
      // CST timezone (UTC+8)
      const year = d.getFullYear()
      const month = String(d.getMonth() + 1).padStart(2, '0')
      const day = String(d.getDate()).padStart(2, '0')
      const hours = String(d.getHours()).padStart(2, '0')
      const minutes = String(d.getMinutes()).padStart(2, '0')
      return `${year}/${month}/${day} ${hours}:${minutes}`
    }
  }
}
</script>

<style scoped>
.terminals-container {
  display: flex;
  height: 100%;
  gap: 2px;
}

.terminals-sidebar {
  width: 14%;
  min-width: 140px;
  background: #fff;
  border-radius: 8px;
  border: 1px solid #e2e8f0;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.sidebar-header {
  padding: 0 16px !important;
  height: 48px !important;
  line-height: 48px !important;
  background: #f8fafc !important;
  border-bottom: 1px solid #e2e8f0 !important;
  font-weight: 600 !important;
  font-size: 14px !important;
  color: #1e293b !important;
  display: flex !important;
  justify-content: space-between !important;
  align-items: center !important;
  box-sizing: border-box !important;
  margin: 0 !important;
}

.header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.header-actions .el-button--text {
  padding: 0;
  color: #6366f1;
  font-size: 12px;
}

.el-dropdown-link {
  cursor: pointer;
  color: #64748b;
  padding: 4px;
}

.el-dropdown-link:hover {
  color: #334155;
}

.sidebar-content {
  flex: 1;
  overflow-y: auto;
  padding: 8px;
}

/* 树形连接线样式 */
.sidebar-content {
  flex: 1;
  overflow-y: auto;
  padding: 8px 8px 8px 0;
}

/* 连接线 - 垂直线 */
.sidebar-content .el-tree-node::before {
  content: '';
  position: absolute;
  left: 11px;
  top: -10px;
  bottom: 18px;
  width: 1px;
  background: #d1d5db;
}

/* 连接线 - 水平线 */
.sidebar-content .el-tree-node::after {
  content: '';
  position: absolute;
  left: 11px;
  top: 18px;
  width: 18px;
  height: 1px;
  background: #d1d5db;
}

/* 根节点不需要垂直线上半部分 */
.sidebar-content .el-tree > .el-tree-node::before {
  display: none;
}

/* 最后一个节点垂直线处理 */
.sidebar-content .el-tree-node.is-last-child::before {
  height: 26px;
}

.sidebar-content .el-tree-node__content {
  position: relative;
  padding-left: 0 !important;
}

.sidebar-content .el-tree-node__expand-icon {
  color: #64748b;
  font-size: 12px;
}

.sidebar-content .el-tree-node__expand-icon.is-leaf {
  color: transparent;
}

/* 移除默认缩进 */
.sidebar-content .el-tree-node {
  padding-left: 20px;
  position: relative;
}

.sidebar-content .el-tree-node__children {
  position: relative;
}

.tree-node {
  display: flex;
  align-items: center;
  flex: 1;
}

.node-icon {
  margin-right: 8px;
  color: #64748b;
}

.node-label {
  font-size: 13px;
}

.terminals-main {
  flex: 1;
  overflow: hidden;
}

.page-card {
  height: 100%;
  display: flex;
  flex-direction: column;
}

.page-card .el-card__body {
  padding: 0;
}

.header-row {
  display: flex !important;
  justify-content: space-between !important;
  align-items: center !important;
  padding: 0 16px !important;
  height: 48px !important;
  line-height: 48px !important;
  border-bottom: 1px solid #f1f5f9 !important;
  box-sizing: border-box !important;
  margin: 0 !important;
}

.header-row > span:first-child {
  font-weight: 600 !important;
  font-size: 14px !important;
  color: #1e293b !important;
  margin: 0 !important;
  padding: 0 !important;
}

/* Override el-card header slot */
.page-card >>> .el-card__header {
  padding: 0 16px !important;
  min-height: 48px !important;
  height: 48px !important;
  line-height: 48px !important;
  box-sizing: border-box !important;
  border-bottom: 1px solid #f1f5f9 !important;
}

/* Drawer Tabs styles */
.drawer-tabs {
  height: 100%;
  display: flex;
  flex-direction: column;
}
.drawer-tabs >>> .el-tabs {
  flex: 1;
  display: flex;
  flex-direction: column;
}
.drawer-tabs >>> .el-tabs__content {
  flex: 1;
  overflow-y: auto;
}
.drawer-tabs >>> .el-tab-pane {
  height: 100%;
}
.drawer-tabs .tab-content {
  padding: 16px;
}
.drawer-tabs .tab-content h4 {
  margin: 0 0 12px 0;
  color: #303133;
  font-size: 14px;
  border-left: 3px solid #0E9472;
  padding-left: 8px;
}
.drawer-tabs .tab-content h4:not(:first-child) {
  margin-top: 20px;
}
.drawer-tabs .empty-tip {
  color: #909399;
  text-align: center;
  padding: 20px;
}
.drawer-footer {
  padding: 12px 16px;
  border-top: 1px solid #eee;
  background: #fafafa;
}

/* Gauge Component */
.gauge-cell {
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
}
.gauge-cell .gauge-bar {
  flex: 1;
  height: 8px;
  background: #e2e8f0;
  
  overflow: hidden;
}
.gauge-cell .gauge-fill {
  height: 100%;
  width: var(--pct, 0%);
  background-color: var(--color, #0E9472);
  
  transition: width 0.3s ease, background-color 0.3s ease;
}
.gauge-cell .gauge-text {
  font-size: 12px;
  font-weight: 500;
  min-width: 42px;
  text-align: right;
  color: #333;
}
</style>

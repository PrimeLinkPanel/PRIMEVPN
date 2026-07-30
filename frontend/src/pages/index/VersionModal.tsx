import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Alert, Button, Collapse, Modal, Tag, Tooltip } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';

import { HttpUtil } from '@/utils';
import { activateOnKey } from '@/utils/a11y';
import type { Status } from '@/models/status';
import GeodataSection from './GeodataSection';
import './VersionModal.css';

interface BusyEvent {
  busy: boolean;
  tip?: string;
}

interface VersionModalProps {
  open: boolean;
  status: Status;
  onClose: () => void;
  onBusy: (e: BusyEvent) => void;
}

const GEOFILES = [
  'geosite.dat',
  'geoip.dat',
  'geosite_IR.dat',
  'geoip_IR.dat',
  'geosite_RU.dat',
  'geoip_RU.dat',
];

export default function VersionModal({ open, status, onClose, onBusy }: VersionModalProps) {
  const { t } = useTranslation();
  const [modal, modalContextHolder] = Modal.useModal();
  const [activeKey, setActiveKey] = useState<string | string[]>('1');

  function updateGeofile(fileName: string) {
    const isSingle = !!fileName;
    modal.confirm({
      title: t('pages.index.geofileUpdateDialog'),
      content: isSingle
        ? t('pages.index.geofileUpdateDialogDesc').replace('#filename#', fileName)
        : t('pages.index.geofilesUpdateDialogDesc'),
      okText: t('confirm'),
      cancelText: t('cancel'),
      onOk: async () => {
        onClose();
        onBusy({ busy: true, tip: t('pages.index.dontRefresh') });
        const url = isSingle
          ? `/panel/api/server/updateGeofile/${fileName}`
          : '/panel/api/server/updateGeofile';
        try {
          await HttpUtil.post(url);
        } finally {
          onBusy({ busy: false });
        }
      },
    });
  }

  const activeKeyStr = Array.isArray(activeKey) ? activeKey[0] : activeKey;
  const currentXrayVersion =
    status?.xray?.version && status.xray.version !== 'Unknown'
      ? `v${status.xray.version}`
      : 'Unknown';

  return (
    <Modal
      open={open}
      title={t('pages.index.xrayUpdates')}
      footer={null}
      onCancel={onClose}
    >
      {modalContextHolder}
      <Collapse
        accordion
        activeKey={activeKey}
        onChange={setActiveKey}
        items={[
          {
            key: '1',
            label: 'Xray',
            children: (
              <>
                <Alert
                  type="info"
                  className="mb-12"
                  showIcon
                  message="PRIMEVPN Custom Xray Core is locked"
                  description="Core switching from the panel is disabled to preserve Speed Limit, Upload/Download Limit, and Core-Level Connection Limit features."
                />
                <div className="version-list">
                  <div className="version-list-item">
                    <Tag color="green">Current Core</Tag>
                    <Tag color="purple">{currentXrayVersion}</Tag>
                  </div>
                </div>
              </>
            ),
          },
          {
            key: '2',
            label: 'Geofiles',
            children: (
              <>
                <div className="version-list">
                  {GEOFILES.map((file, index) => (
                    <div key={file} className="version-list-item">
                      <Tag color={index % 2 === 0 ? 'purple' : 'green'}>{file}</Tag>
                      <Tooltip title={t('update')}>
                        <ReloadOutlined
                          className="reload-icon"
                          role="button"
                          tabIndex={0}
                          aria-label={t('update')}
                          onClick={() => updateGeofile(file)}
                          onKeyDown={activateOnKey(() => updateGeofile(file))}
                        />
                      </Tooltip>
                    </div>
                  ))}
                </div>
                <div className="actions-row">
                  <Button onClick={() => updateGeofile('')}>
                    {t('pages.index.geofilesUpdateAll')}
                  </Button>
                </div>
              </>
            ),
          },
          {
            key: '3',
            label: t('pages.index.geodataTitle'),
            children: (
              <GeodataSection
                active={activeKeyStr === '3'}
                onBusy={onBusy}
                onClose={onClose}
              />
            ),
          },
        ]}
      />
    </Modal>
  );
}
